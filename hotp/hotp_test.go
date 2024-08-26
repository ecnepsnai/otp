/**
 *  Copyright 2014 Paul Querna
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */

package hotp

import (
	"bytes"
	"encoding/base32"
	"strings"
	"testing"

	"github.com/ecnepsnai/otp"
)

type tc struct {
	Counter uint64
	TOTP    string
	Mode    otp.Algorithm
	Secret  string
}

var (
	secSha1 = base32.StdEncoding.EncodeToString([]byte("12345678901234567890"))

	rfcMatrixTCs = []tc{
		{0, "755224", otp.AlgorithmSHA1, secSha1},
		{1, "287082", otp.AlgorithmSHA1, secSha1},
		{2, "359152", otp.AlgorithmSHA1, secSha1},
		{3, "969429", otp.AlgorithmSHA1, secSha1},
		{4, "338314", otp.AlgorithmSHA1, secSha1},
		{5, "254676", otp.AlgorithmSHA1, secSha1},
		{6, "287922", otp.AlgorithmSHA1, secSha1},
		{7, "162583", otp.AlgorithmSHA1, secSha1},
		{8, "399871", otp.AlgorithmSHA1, secSha1},
		{9, "520489", otp.AlgorithmSHA1, secSha1},
	}
)

// Test values from http://tools.ietf.org/html/rfc4226#appendix-D
func TestValidateRFCMatrix(t *testing.T) {

	for _, tx := range rfcMatrixTCs {
		valid, err := ValidateCustom(tx.TOTP, tx.Counter, tx.Secret,
			ValidateOpts{
				Digits:    otp.DigitsSix,
				Algorithm: tx.Mode,
			})
		if err != nil {
			t.Fatalf("unexpected error totp=%s mode=%v counter=%v", tx.TOTP, tx.Mode, tx.Counter)
		}
		if !valid {
			t.Fatalf("unexpected totp failure totp=%s mode=%v counter=%v", tx.TOTP, tx.Mode, tx.Counter)
		}
	}
}

func TestGenerateRFCMatrix(t *testing.T) {
	for _, tx := range rfcMatrixTCs {
		passcode, err := GenerateCodeCustom(tx.Secret, tx.Counter,
			ValidateOpts{
				Digits:    otp.DigitsSix,
				Algorithm: tx.Mode,
			})
		if err != nil {
			t.Fatalf("Error: %s", err.Error())
		}
		if tx.TOTP != passcode {
			t.Fatalf("'%s' does not equal '%s'", tx.TOTP, passcode)
		}
	}
}

func TestGenerateCodeCustom(t *testing.T) {
	secSha1 := base32.StdEncoding.EncodeToString([]byte("12345678901234567890"))

	code, err := GenerateCodeCustom("foo", 1, ValidateOpts{})
	print(code)
	if otp.ErrValidateSecretInvalidBase32 != err {
		t.Fatalf("Decoding of secret as base32 failed.")
	}
	if "" != code {
		t.Fatalf("Code should be empty string when we have an error.")
	}

	code, err = GenerateCodeCustom(secSha1, 1, ValidateOpts{})
	if 6 != len(code) {
		t.Fatalf("Code should be 6 digits when we have not an error.")
	}
	if err != nil {
		t.Fatalf("Expected no error.")
	}
}

func TestValidateInvalid(t *testing.T) {
	secSha1 := base32.StdEncoding.EncodeToString([]byte("12345678901234567890"))

	valid, err := ValidateCustom("foo", 11, secSha1,
		ValidateOpts{
			Digits:    otp.DigitsSix,
			Algorithm: otp.AlgorithmSHA1,
		})
	if otp.ErrValidateInputInvalidLength != err {
		t.Fatalf("Expected Invalid length error.")
	}
	if false != valid {
		t.Fatalf("Valid should be false when we have an error.")
	}

	valid, err = ValidateCustom("foo", 11, secSha1,
		ValidateOpts{
			Digits:    otp.DigitsEight,
			Algorithm: otp.AlgorithmSHA1,
		})
	if otp.ErrValidateInputInvalidLength != err {
		t.Fatalf("Expected Invalid length error.")
	}
	if false != valid {
		t.Fatalf("Valid should be false when we have an error.")
	}

	valid, err = ValidateCustom("000000", 11, secSha1,
		ValidateOpts{
			Digits:    otp.DigitsSix,
			Algorithm: otp.AlgorithmSHA1,
		})
	if err != nil {
		t.Fatalf("Expected no error.")
	}
	if false != valid {
		t.Fatalf("Valid should be false.")
	}

	valid = Validate("000000", 11, secSha1)
	if false != valid {
		t.Fatalf("Valid should be false.")
	}
}

// This tests for issue #10 - secrets without padding
func TestValidatePadding(t *testing.T) {
	valid, err := ValidateCustom("831097", 0, "JBSWY3DPEHPK3PX",
		ValidateOpts{
			Digits:    otp.DigitsSix,
			Algorithm: otp.AlgorithmSHA1,
		})
	if err != nil {
		t.Fatalf("Expected no error.")
	}
	if true != valid {
		t.Fatalf("Valid should be true.")
	}
}

func TestValidateLowerCaseSecret(t *testing.T) {
	valid, err := ValidateCustom("831097", 0, "jbswy3dpehpk3px",
		ValidateOpts{
			Digits:    otp.DigitsSix,
			Algorithm: otp.AlgorithmSHA1,
		})
	if err != nil {
		t.Fatalf("Expected no error.")
	}
	if true != valid {
		t.Fatalf("Valid should be true.")
	}
}

func TestGenerate(t *testing.T) {
	k, err := Generate(GenerateOpts{
		Issuer:      "SnakeOil",
		AccountName: "alice@example.com",
	})
	if err != nil {
		t.Fatalf("generate basic HOTP")
	}
	if "SnakeOil" != k.Issuer() {
		t.Fatalf("Extracting Issuer")
	}
	if "alice@example.com" != k.AccountName() {
		t.Fatalf("Extracting Account Name")
	}
	if 16 != len(k.Secret()) {
		t.Fatalf("Secret is 16 bytes long as base32.")
	}

	k, err = Generate(GenerateOpts{
		Issuer:      "Snake Oil",
		AccountName: "alice@example.com",
	})
	if err != nil {
		t.Fatalf("issuer with a space in the name")
	}
	if !strings.Contains(k.String(), "issuer=Snake%20Oil") {
		t.FailNow()
	}

	k, err = Generate(GenerateOpts{
		Issuer:      "SnakeOil",
		AccountName: "alice@example.com",
		SecretSize:  20,
	})
	if err != nil {
		t.Fatalf("generate larger HOTP")
	}
	if 32 != len(k.Secret()) {
		t.Fatalf("Secret is 32 bytes long as base32.")
	}

	k, err = Generate(GenerateOpts{
		Issuer:      "",
		AccountName: "alice@example.com",
	})
	if otp.ErrGenerateMissingIssuer != err {
		t.Fatalf("generate missing issuer")
	}
	if k != nil {
		t.Fatalf("key should be nil on error.")
	}

	k, err = Generate(GenerateOpts{
		Issuer:      "Foobar, Inc",
		AccountName: "",
	})
	if otp.ErrGenerateMissingAccountName != err {
		t.Fatalf("generate missing account name.")
	}
	if k != nil {
		t.Fatalf("key should be nil on error.")
	}

	k, err = Generate(GenerateOpts{
		Issuer:      "SnakeOil",
		AccountName: "alice@example.com",
		SecretSize:  17, // anything that is not divisible by 5, really
	})
	if err != nil {
		t.Fatalf("Secret size is valid when length not divisible by 5.")
	}
	if strings.Contains(k.Secret(), "=") {
		t.Fatalf("Secret has no escaped characters.")
	}

	k, err = Generate(GenerateOpts{
		Issuer:      "SnakeOil",
		AccountName: "alice@example.com",
		Secret:      []byte("helloworld"),
	})
	if err != nil {
		t.Fatalf("Secret generation failed")
	}
	sec, err := b32NoPadding.DecodeString(k.Secret())
	if err != nil {
		t.Fatalf("Secret was not valid base32")
	}
	if !bytes.Equal(sec, []byte("helloworld")) {
		t.Fatalf("Specified Secret was not kept")
	}
}
