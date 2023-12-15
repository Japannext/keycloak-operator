package utils

import (
	"context"
	"fmt"
	"reflect"
	"strconv"
	"strings"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	diff "github.com/r3labs/diff/v3"
)

func makePath(path []string) string {
	var b strings.Builder
	if len(path) == 0 {
		return "???"
	}
	for _, v := range path {
		if _, err := strconv.Atoi(v); err == nil {
			b.WriteString(fmt.Sprintf("[%s]", v))
		} else {
			b.WriteString(fmt.Sprintf(".%s", v))
		}
	}
	return b.String()
}

func EventUpdate(r *BaseReconciler, ctx context.Context, i client.Object, changelog diff.Changelog) {
	logger := log.FromContext(ctx)
	r.Event(i, "Normal", "Update", fmt.Sprintf("Change triggered by %d field changes", len(changelog)))
	for _, c := range changelog {
		m1 := fmt.Sprintf("change triggered by %s (%s): ", makePath(c.Path), c.Type)
		var m2 string
		switch c.Type {
		case "create":
			v := reflect.ValueOf(c.To)
			if v.Kind() == reflect.Ptr {
				v = v.Elem()
			}
			m2 = fmt.Sprintf("<none> -> %+v", v)
		case "delete":
			v := reflect.ValueOf(c.From)
			if v.Kind() == reflect.Ptr {
				v = v.Elem()
			}
			m2 = fmt.Sprintf("%+v -> <none>", v)
		case "update":
			x := reflect.ValueOf(c.From)
			y := reflect.ValueOf(c.To)
			if x.Kind() == reflect.Ptr {
				x = x.Elem()
			}
			if y.Kind() == reflect.Ptr {
				y = y.Elem()
			}
			m2 = fmt.Sprintf("%+v -> %+v", x, y)
		default:
			m2 = "???"
		}
		logger.V(2).Info(m1 + m2)
	}
}
