/*
Copyright 2021 Adevinta
*/
package http

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/julienschmidt/httprouter"

	"github.com/adevinta/vulcan-agent/api"
	"github.com/adevinta/vulcan-agent/log"
)

// ErrorResponse represents and http response when an error processing
// a request occurs.
type ErrorResponse struct {
	Error string `json:"error,omitempty"`
}

// StatsResponse represents a stats response.
type StatsResponse struct {
	api.Stats `json:"stats"`
}

type Router interface {
	GET(path string, handle httprouter.Handle)
	PATCH(path string, handle httprouter.Handle)
}

// API defines the shape of the services that the http.REST exposes.
type API interface {
	CheckUpdate(s api.CheckState) error
	Stats() (api.Stats, error)
}

// REST exposes an API using http REST endpoints.
type REST struct {
	api API
	log log.Logger
}

// NewREST returns a REST components that exposes a given API using http REST
// endpoints through the given router.
func NewREST(log log.Logger, a API, router *httprouter.Router) *REST {
	r := &REST{
		api: a,
		log: log,
	}
	router.PATCH("/check/:id", r.handleCheckUpdate)
	router.GET("/stats", r.handleStats)
	return r
}

func (re *REST) handleCheckUpdate(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	id := ps.ByName("id")
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		err = fmt.Errorf("error reading check update request: %v", err.Error())
		re.log.Errorf("error: %+v", err)
		writeJSONResponse(w, http.StatusBadRequest, ErrorResponse{err.Error()})
		return
	}
	var state = new(api.CheckState)
	err = json.Unmarshal(body, state)
	if err != nil {
		err = fmt.Errorf("error decoding check update request: %v", err.Error())
		re.log.Errorf("error: %+v", err)
		writeJSONResponse(w, http.StatusBadRequest, ErrorResponse{err.Error()})
		return
	}
	state.ID = id
	err = re.api.CheckUpdate(*state)
	if err != nil {
		err = fmt.Errorf("updating check state, %v", err.Error())
		re.log.Errorf(err.Error())
		writeJSONResponse(w, http.StatusInternalServerError, ErrorResponse{err.Error()})
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (re *REST) handleStats(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	stats, err := re.api.Stats()
	if err != nil {
		err = fmt.Errorf("error updating check state: %v", err.Error())
		re.log.Errorf("error: %+v", err)
		writeJSONResponse(w, http.StatusInternalServerError, ErrorResponse{err.Error()})
		return
	}
	resp := StatsResponse{stats}
	writeJSONResponse(w, http.StatusOK, resp)
}

func writeJSONResponse(w http.ResponseWriter, code int, v interface{}) {
	w.WriteHeader(code)
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	if err := enc.Encode(v); err != nil {
		http.Error(w, "", http.StatusInternalServerError)
	}
}
