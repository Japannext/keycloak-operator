package utils

import (
	"context"

	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

func AppendOwnerReferences(ctx context.Context, c client.Client, s *runtime.Scheme, i client.Object, owner client.Object) error {
	refs := i.GetOwnerReferences()
	if len(refs) == 0 {
		controllerutil.SetOwnerReference(owner, i, s)
		return c.Update(ctx, i)
	}
	return nil
}
