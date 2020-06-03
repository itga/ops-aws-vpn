package clientapi

import (
	"net/http"

	"github.com/itga/ops-aws-vpn/pkg/api"

	"github.com/gorilla/mux"
	"github.com/itga/ops-aws-vpn/pkg/pki"
)

func apiGetCert(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)

	serial, err := pki.DecodeSerial(vars["serial"])
	if err != nil {
		api.ErrorResponse(w, http.StatusBadRequest, err, "Invalid serial")
		return
	}

	cert, err := apiPKI.GetCertBySerial(r.Context(), serial)
	if err != nil {
		api.ErrorResponse(w, http.StatusInternalServerError, err, "Error obtaining certificate")
		return
	}

	_, userInfo, err := api.GetAPIGWPrincipal(r)
	if err != nil {
		api.ErrorResponse(w, http.StatusInternalServerError, err, "Error obtaining principal")
		return
	}

	if cert == nil || cert.Subject != userInfo.Email {
		api.ErrorResponse(w, http.StatusNotFound, nil, "Not found")
		return
	}

	api.JsonResponse(w, http.StatusOK, cert)
}
