/*******************************************************************************
jsonwt - JSON Web Tokens
Copyright (c) 2022 Michael D Henderson

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
******************************************************************************/

package jsonwt

import "errors"

var ErrBadFactory = errors.New("bad factory")
var ErrBadRequest = errors.New("bad request")
var ErrBadToken = errors.New("bad token")
var ErrExpired = errors.New("expired")
var ErrInvalid = errors.New("invalid token")
var ErrInvalidSignature = errors.New("invalid signature")
var ErrMissingAuthHeader = errors.New("missing auth header")
var ErrMissingScope = errors.New("missing scope")
var ErrMissingSigner = errors.New("missing signer")
var ErrNotBearer = errors.New("not a bearer token")
var ErrNotMyKID = errors.New("not my kid")
var ErrUnauthorized = errors.New("unauthorized")
