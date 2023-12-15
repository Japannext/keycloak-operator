package v1alpha2

func Unwrap[T any](v *T) T {
	if v != nil {
		return *v
	}
	return *new(T)
}

func Ptr[T any](v T) *T {
	return &v
}
