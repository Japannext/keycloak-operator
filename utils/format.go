package utils

import (
	"fmt"
	"reflect"
	"strconv"
	"strings"

	diff "github.com/r3labs/diff/v3"
)

func FormatChangelog(changelog diff.Changelog) string {
	var buf []string
	for _, ch := range changelog {
		var b strings.Builder
		for _, v := range ch.Path {
			if _, err := strconv.Atoi(v); err == nil {
				b.WriteString(fmt.Sprintf("[%s]", v))
			} else {
				b.WriteString(fmt.Sprintf(".%s", v))
			}
		}
		path := b.String()
		var s string
		switch ch.Type {
		case "delete":
			x := reflect.ValueOf(ch.From)
			if x.Kind() == reflect.Ptr {
				x.Elem()
			}
			s = fmt.Sprintf("%s: %+v -> <not-set>", path, x)
		case "create":
			y := reflect.ValueOf(ch.To)
			if y.Kind() == reflect.Ptr {
				y.Elem()
			}
			s = fmt.Sprintf("%s: <not-set> -> %+v", path, y)
		case "update":
			x := reflect.ValueOf(ch.From)
			if x.Kind() == reflect.Ptr {
				x.Elem()
			}
			y := reflect.ValueOf(ch.To)
			if y.Kind() == reflect.Ptr {
				y.Elem()
			}
			s = fmt.Sprintf("%s: %+v -> %+v", path, x, ch.To)
		default:
			s = "<unknown operator>"
		}
		buf = append(buf, s)
	}
	return strings.Join(buf, ", ")
}
