package handlers

import (
	"encoding/json"
	"errors"
	"net/http"
)

type APIError struct {
	Status  int
	Code    string
	Message string
	Err     error
}

func (e *APIError) Error() string {
	if e.Err != nil {
		return e.Err.Error()
	}
	return e.Message
}

func (e *APIError) Unwrap() error {
	return e.Err
}

func newAPIError(status int, code string, message string, err error) *APIError {
	return &APIError{
		Status:  status,
		Code:    code,
		Message: message,
		Err:     err,
	}
}

func apiErrorFrom(err error, fallbackMessage string) *APIError {
	var apiErr *APIError
	if errors.As(err, &apiErr) {
		return apiErr
	}
	return newAPIError(http.StatusBadRequest, "operation_failed", fallbackMessage, err)
}

func writeAPIError(w http.ResponseWriter, apiErr *APIError) {
	status := apiErr.Status
	if status == 0 {
		status = http.StatusInternalServerError
	}

	response := map[string]string{
		"code":  apiErr.Code,
		"error": apiErr.Message,
	}
	if response["code"] == "" {
		response["code"] = "error"
	}

	responseBytes, err := json.Marshal(response)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	w.Write(responseBytes)
}
