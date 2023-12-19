package utils

import (
	"testing"
	"time"

	ctrl "sigs.k8s.io/controller-runtime"

	"github.com/stretchr/testify/assert"
)

func TestHandleErrorReschedule(t *testing.T) {
	e := Reschedule{RequeueAfter: 1 * time.Minute}
	assert := assert.New(t)
	res, err := HandleError(e)
	assert.Equal(1*time.Minute, res.RequeueAfter, "requeue after 1 minute")
	assert.NoError(err, "no error")
}

func TestHandleErrorNoReschedule(t *testing.T) {
	e := NoReschedule{}
	assert := assert.New(t)
	res, err := HandleError(e)
	assert.Equal(ctrl.Result{}, res, "no requeue")
	assert.NoError(err, "no error")
}
