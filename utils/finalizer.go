package utils

import (
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

func HasFinalizer(i client.Object) bool {
	return controllerutil.ContainsFinalizer(i, finalizer)
}

func NoFinalizer(i client.Object) bool {
	return !controllerutil.ContainsFinalizer(i, finalizer)
}

func MarkedAsDeleted(i client.Object) bool {
	return !i.GetDeletionTimestamp().IsZero()
}

const (
	finalizer = "keycloak.japannext.co.jp/finalizer"
)

// Append the finalizer to the object
func (r *BaseReconciler) AppendFinalizer(ctx context.Context, i client.Object) error {
	if !controllerutil.ContainsFinalizer(i, finalizer) {
		opts := &client.PatchOptions{FieldManager: "keycloak-operator"}
		patch := client.RawPatch(types.MergePatchType, []byte(`{"metadata": {"finalizers": ["keycloak.japannext.co.jp/finalizer"]}}`))
		if err := r.Patch(ctx, i, patch, opts); err != nil {
			return fmt.Errorf("failed to add finalizer: %w", err)
		}
	}
	return nil
}

func (r *BaseReconciler) RemoveFinalizer(ctx context.Context, i client.Object) error {
	if controllerutil.ContainsFinalizer(i, finalizer) {
		opts := &client.PatchOptions{FieldManager: "keycloak-operator"}
		patch := client.RawPatch(types.MergePatchType, []byte(`{"metadata": {"finalizers": null}}`))
		if err := r.Patch(ctx, i, patch, opts); err != nil {
			return fmt.Errorf("failed to remove finalizer: %w", err)
		}
	}
	return nil
}
