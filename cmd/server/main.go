/*
 * jsonwt - JSON Web Tokens
 * Copyright (c) 2022 Michael D Henderson
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

// Package main implements a server for testing the JSONWT API.
package main

import (
	"encoding/json"
	"github.com/mdhender/jsonwt"
	"github.com/mdhender/jsonwt/signers"
	"log"
	"net/http"
	"time"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

type AUTHRESPONSE struct {
	Data struct {
		Token string `json:"token"`
	} `json:"data"`
}

type CLAIM struct {
	Roles []string
}

func run() error {
	s, err := signers.NewHS256([]byte("secret"))
	if err != nil {
		return err
	}
	f := jsonwt.NewFactory("me", s)
	log.Printf("using factory %q\n", f.ID())

	claim := CLAIM{
		Roles: []string{"one", "two"},
	}

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
			return
		}

		switch r.Method {
		case http.MethodGet:
			t, err := f.Token(91*time.Second, claim)
			if err != nil {
				log.Printf("%s %s: %+v\n", r.Method, r.URL, err)
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				return
			}
			var rsp AUTHRESPONSE
			rsp.Data.Token = t.String()
			b, err := json.MarshalIndent(rsp, "", "  ")
			if err != nil {
				log.Printf("%s %s: %+v\n", r.Method, r.URL, err)
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				return
			}
			log.Printf("%s %s: %s\n", r.Method, r.URL, t.String())
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(b)
		case http.MethodPost:
			t := jsonwt.FromRequest(r)
			if t == nil {
				log.Printf("%s %s: no bearer token\n", r.Method, r.URL)
				http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
				return
			}
			err := f.Validate(t)
			if err != nil {
				log.Printf("%s %s: %+v\n", r.Method, r.URL, err)
				http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
				return
			}
			var c CLAIM
			err = t.Claim(&c)
			if err != nil {
				log.Printf("%s %s: %+v\n", r.Method, r.URL, err)
				http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
				return
			}
			log.Printf("%s %s: %+v\n", r.Method, r.URL, c)
			w.WriteHeader(http.StatusNoContent)
		default:
			log.Printf("%s %s: not found\n", r.Method, r.URL)
			http.Error(w, http.StatusText(http.StatusNotFound), http.StatusNotFound)
		}
	})

	log.Printf("listening on :8080\n")
	return http.ListenAndServe(":8080", nil)
}
