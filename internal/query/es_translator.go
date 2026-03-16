package query

import (
	"fmt"
	"strings"
)

// TranslateResult holds the Elasticsearch query DSL and additional
// request parameters derived from the parsed query AST.
type TranslateResult struct {
	// Query is the ES query DSL (the "query" field of a search request).
	Query map[string]any

	// Sort is the ES sort clause (nil if no sort pipe).
	Sort []map[string]any

	// Size is the result limit (0 means use default).
	Size int

	// Source is the list of fields to return (nil means all).
	Source []string

	// Aggs is the ES aggregation clause (nil if no aggregation).
	Aggs map[string]any

	// From is the offset for pagination (used by tail pipe).
	From int
}

// Translate converts a parsed Query AST into Elasticsearch DSL.
// Returns a TranslateResult with the query, sort, size, and source fields.
func Translate(q *Query) (*TranslateResult, error) {
	result := &TranslateResult{}

	// Translate the filter expression into an ES query.
	if q.Filter != nil {
		esQuery, err := translateNode(q.Filter)
		if err != nil {
			return nil, fmt.Errorf("translating filter: %w", err)
		}
		result.Query = esQuery
	} else {
		result.Query = map[string]any{"match_all": map[string]any{}}
	}

	// Translate aggregation if present.
	if q.Agg != nil {
		aggs, err := translateAgg(q.Agg)
		if err != nil {
			return nil, fmt.Errorf("translating aggregation: %w", err)
		}
		result.Aggs = aggs
		// For aggregations, we typically don't need hits.
		result.Size = 0
	}

	// Process pipe stages.
	for _, pipe := range q.Pipes {
		switch p := pipe.(type) {
		case *SortPipe:
			order := "asc"
			if p.Desc {
				order = "desc"
			}
			result.Sort = append(result.Sort, map[string]any{
				p.Field: map[string]any{"order": order},
			})

		case *LimitPipe:
			result.Size = p.N

		case *HeadPipe:
			result.Size = p.N

		case *TailPipe:
			// Tail requires knowing total count — we approximate by sorting
			// in reverse and limiting. The caller can handle this specially.
			result.Size = p.N

		case *FieldsPipe:
			result.Source = p.Fields
		}
	}

	return result, nil
}

// translateNode recursively converts an AST node to ES DSL.
func translateNode(node Node) (map[string]any, error) {
	switch n := node.(type) {
	case *CompareExpr:
		return translateCompare(n)
	case *BoolExpr:
		return translateBool(n)
	case *ExistsExpr:
		return translateExists(n)
	case *InExpr:
		return translateIn(n)
	default:
		return nil, fmt.Errorf("unknown AST node type: %T", node)
	}
}

// translateCompare converts a field comparison to ES DSL.
func translateCompare(expr *CompareExpr) (map[string]any, error) {
	field := expr.Field

	switch expr.Operator {
	case OpEquals:
		// Check for wildcard pattern.
		if strings.Contains(expr.Value, "*") || strings.Contains(expr.Value, "?") {
			return map[string]any{
				"wildcard": map[string]any{
					field: map[string]any{"value": expr.Value},
				},
			}, nil
		}
		return map[string]any{
			"term": map[string]any{field: expr.Value},
		}, nil

	case OpNotEquals:
		inner := map[string]any{
			"term": map[string]any{field: expr.Value},
		}
		return map[string]any{
			"bool": map[string]any{
				"must_not": []any{inner},
			},
		}, nil

	case OpGreater:
		return map[string]any{
			"range": map[string]any{
				field: map[string]any{"gt": expr.Value},
			},
		}, nil

	case OpLess:
		return map[string]any{
			"range": map[string]any{
				field: map[string]any{"lt": expr.Value},
			},
		}, nil

	case OpGTE_Q:
		return map[string]any{
			"range": map[string]any{
				field: map[string]any{"gte": expr.Value},
			},
		}, nil

	case OpLTE_Q:
		return map[string]any{
			"range": map[string]any{
				field: map[string]any{"lte": expr.Value},
			},
		}, nil

	default:
		return nil, fmt.Errorf("unsupported operator %q", expr.Operator)
	}
}

// translateBool converts a boolean expression to ES DSL.
func translateBool(expr *BoolExpr) (map[string]any, error) {
	switch expr.Op {
	case BoolAnd:
		left, err := translateNode(expr.Left)
		if err != nil {
			return nil, err
		}
		right, err := translateNode(expr.Right)
		if err != nil {
			return nil, err
		}

		// Flatten nested ANDs into a single must clause.
		must := flattenBoolClause(left, right, "must")
		return map[string]any{
			"bool": map[string]any{"must": must},
		}, nil

	case BoolOr:
		left, err := translateNode(expr.Left)
		if err != nil {
			return nil, err
		}
		right, err := translateNode(expr.Right)
		if err != nil {
			return nil, err
		}

		should := flattenBoolClause(left, right, "should")
		return map[string]any{
			"bool": map[string]any{
				"should":               should,
				"minimum_should_match": 1,
			},
		}, nil

	case BoolNot:
		inner, err := translateNode(expr.Left)
		if err != nil {
			return nil, err
		}
		return map[string]any{
			"bool": map[string]any{
				"must_not": []any{inner},
			},
		}, nil

	default:
		return nil, fmt.Errorf("unsupported boolean operator %q", expr.Op)
	}
}

// flattenBoolClause merges two clauses into a single slice, flattening
// if either clause is already a bool with the same clause type.
func flattenBoolClause(left, right map[string]any, clauseType string) []any {
	var clauses []any

	// Try to flatten left.
	if extracted := extractBoolClauses(left, clauseType); extracted != nil {
		clauses = append(clauses, extracted...)
	} else {
		clauses = append(clauses, left)
	}

	// Try to flatten right.
	if extracted := extractBoolClauses(right, clauseType); extracted != nil {
		clauses = append(clauses, extracted...)
	} else {
		clauses = append(clauses, right)
	}

	return clauses
}

// extractBoolClauses checks if a query is a bool with only the given clause
// type and returns its contents for flattening.
func extractBoolClauses(query map[string]any, clauseType string) []any {
	boolMap, ok := query["bool"].(map[string]any)
	if !ok {
		return nil
	}

	// Only flatten if the bool has exactly one key matching clauseType.
	if len(boolMap) != 1 {
		// Has multiple keys (e.g., "should" + "minimum_should_match").
		// For "should", we also check for exactly 2 keys.
		if clauseType == "should" && len(boolMap) == 2 {
			if _, hasMSM := boolMap["minimum_should_match"]; hasMSM {
				if clauses, ok := boolMap[clauseType].([]any); ok {
					return clauses
				}
			}
		}
		return nil
	}

	clauses, ok := boolMap[clauseType].([]any)
	if !ok {
		return nil
	}
	return clauses
}

// translateExists converts an exists expression to ES DSL.
func translateExists(expr *ExistsExpr) (map[string]any, error) {
	return map[string]any{
		"exists": map[string]any{"field": expr.Field},
	}, nil
}

// translateIn converts an IN expression to ES DSL using a terms query.
func translateIn(expr *InExpr) (map[string]any, error) {
	values := make([]any, len(expr.Values))
	for i, v := range expr.Values {
		values[i] = v
	}
	return map[string]any{
		"terms": map[string]any{expr.Field: values},
	}, nil
}

// translateAgg converts an aggregation expression to ES DSL.
func translateAgg(agg *AggExpr) (map[string]any, error) {
	// Build nested aggregation from group-by fields.
	// For count() by user.name, host.name:
	// { "group_by_user.name": { "terms": { "field": "user.name" },
	//   "aggs": { "group_by_host.name": { "terms": { "field": "host.name" } } } } }

	if len(agg.GroupBy) == 0 {
		return nil, fmt.Errorf("aggregation requires at least one group-by field")
	}

	// Build from innermost to outermost.
	var innerAgg map[string]any

	// For non-count functions, add a metric aggregation at the innermost level.
	if agg.Function != AggCount && agg.Field != "" {
		metricName := fmt.Sprintf("%s_%s", agg.Function, agg.Field)
		innerAgg = map[string]any{
			metricName: map[string]any{
				string(agg.Function): map[string]any{"field": agg.Field},
			},
		}
	}

	// Build group-by terms aggregations from inside out.
	for i := len(agg.GroupBy) - 1; i >= 0; i-- {
		field := agg.GroupBy[i]
		aggName := fmt.Sprintf("group_by_%s", field)

		termsAgg := map[string]any{
			aggName: map[string]any{
				"terms": map[string]any{
					"field": field,
					"size":  1000,
				},
			},
		}

		if innerAgg != nil {
			termsAgg[aggName].(map[string]any)["aggs"] = innerAgg
		}

		innerAgg = termsAgg
	}

	return innerAgg, nil
}

// BuildSearchBody constructs a complete ES search request body from a
// TranslateResult. This is what gets sent to Elasticsearch.
func BuildSearchBody(tr *TranslateResult) map[string]any {
	body := map[string]any{
		"query": tr.Query,
	}

	if tr.Size > 0 {
		body["size"] = tr.Size
	}

	if len(tr.Sort) > 0 {
		body["sort"] = tr.Sort
	}

	if tr.Source != nil {
		body["_source"] = tr.Source
	}

	if tr.Aggs != nil {
		body["aggs"] = tr.Aggs
	}

	if tr.From > 0 {
		body["from"] = tr.From
	}

	return body
}
