package pactidentity

// The Keys section of contract/contract.json: a body for each function it declares, which
// api.go's `functions` map dispatches by name, and the helpers only these use.

import "encoding/json"

func callGenerateKey(args json.RawMessage) json.RawMessage {
	var a struct {
		Alg *string `json:"alg"`
	}
	if err := decodeArgs(args, &a); err != nil {
		return failErr(codeFor(err, codeArgs), err)
	}
	alg, err := needStr(a.Alg, "alg")
	if err != nil {
		return failErr(codeArgs, err)
	}
	priv, err := GenerateKey(alg)
	if err != nil {
		return failErr("unsupported", err)
	}
	o, err := keyOut(priv)
	if err != nil {
		return failErr(codeFor(err, "parse"), err)
	}
	return ok(o)
}

// §2.1. Two calls rather than one so a wallet never hardcodes the salt: the constant lives here,
// the vectors prove it, and a caller that gets it wrong fails loudly instead of quietly becoming
// somebody else.
func callPrfSalt(args json.RawMessage) json.RawMessage {
	return ok(map[string]any{"salt": B64(PrfSalt()), "infos": DerivationInfos})
}

func callDeriveSeed(args json.RawMessage) json.RawMessage {
	var a struct {
		Prf  B64     `json:"prf"`
		Info *string `json:"info"`
	}
	if err := decodeArgs(args, &a); err != nil {
		return failErr(codeFor(err, codeArgs), err)
	}
	if err := need(a.Prf, "prf"); err != nil {
		return failErr(codeArgs, err)
	}
	info, err := needStr(a.Info, "info")
	if err != nil {
		return failErr(codeArgs, err)
	}
	seed, err := DeriveSeed(a.Prf, info)
	if err != nil {
		return failErr(codeArgs, err)
	}
	return ok(map[string]any{"seed": B64(seed)})
}

func callKeyFromSeed(args json.RawMessage) json.RawMessage {
	var a struct {
		Alg  *string `json:"alg"`
		Seed B64     `json:"seed"`
	}
	if err := decodeArgs(args, &a); err != nil {
		return failErr(codeFor(err, codeArgs), err)
	}
	if err := need(a.Seed, "seed"); err != nil {
		return failErr(codeArgs, err)
	}
	alg, err := needStr(a.Alg, "alg")
	if err != nil {
		return failErr(codeArgs, err)
	}
	priv, err := KeyFromSeed(alg, a.Seed)
	if err != nil {
		return failErr(codeFor(err, "parse"), err)
	}
	o, err := keyOut(priv)
	if err != nil {
		return failErr(codeFor(err, "parse"), err)
	}
	return ok(o)
}

func callPublicKey(args json.RawMessage) json.RawMessage {
	var a struct {
		PKCS8 B64 `json:"pkcs8"`
	}
	if err := decodeArgs(args, &a); err != nil {
		return failErr(codeFor(err, codeArgs), err)
	}
	priv, err := privIn(a.PKCS8, "pkcs8")
	if err != nil {
		return failErr(codeFor(err, "parse"), err)
	}
	pub := priv.Public()
	return ok(map[string]any{"alg": priv.Alg, "spki": B64url(pub.SPKI), "fingerprint": Fingerprint(pub.SPKI)})
}

func callKeyInfo(args json.RawMessage) json.RawMessage {
	var a struct {
		SPKI B64 `json:"spki"`
	}
	if err := decodeArgs(args, &a); err != nil {
		return failErr(codeFor(err, codeArgs), err)
	}
	pub, err := pubIn(a.SPKI, "spki")
	if err != nil {
		return failErr(codeFor(err, "parse"), err)
	}
	return ok(map[string]any{"alg": pub.Alg, "fingerprint": Fingerprint(pub.SPKI), "key_id": B64url(KeyID(pub.SPKI))})
}

func callSign(args json.RawMessage) json.RawMessage {
	var a struct {
		PKCS8 B64 `json:"pkcs8"`
		Data  B64 `json:"data"`
	}
	if err := decodeArgs(args, &a); err != nil {
		return failErr(codeFor(err, codeArgs), err)
	}
	priv, err := privIn(a.PKCS8, "pkcs8")
	if err != nil {
		return failErr(codeFor(err, "parse"), err)
	}
	if err := need(a.Data, "data"); err != nil {
		return failErr(codeArgs, err)
	}
	sig, err := SignDetached(priv, a.Data)
	if err != nil {
		return failErr(codeFor(err, "parse"), err)
	}
	return ok(map[string]any{"sig": B64url(sig)})
}

func callVerify(args json.RawMessage) json.RawMessage {
	var a struct {
		SPKI B64 `json:"spki"`
		Data B64 `json:"data"`
		Sig  B64 `json:"sig"`
	}
	if err := decodeArgs(args, &a); err != nil {
		return failErr(codeFor(err, codeArgs), err)
	}
	pub, err := pubIn(a.SPKI, "spki")
	if err != nil {
		return failErr(codeFor(err, "parse"), err)
	}
	if err := need(a.Data, "data"); err != nil {
		return failErr(codeArgs, err)
	}
	if err := need(a.Sig, "sig"); err != nil {
		return failErr(codeArgs, err)
	}
	return ok(map[string]any{"valid": VerifyDetached(pub, a.Data, a.Sig)})
}

func keyOut(priv *PrivateKey) (map[string]any, error) {
	pkcs8, err := priv.PKCS8()
	if err != nil {
		return nil, err
	}
	pub := priv.Public()
	return map[string]any{"alg": priv.Alg, "pkcs8": B64url(pkcs8), "spki": B64url(pub.SPKI), "fingerprint": Fingerprint(pub.SPKI)}, nil
}
