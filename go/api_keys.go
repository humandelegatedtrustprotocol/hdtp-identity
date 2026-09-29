package pactidentity

// The Keys section of contract/contract.json: a body for each function it declares, which
// api.go's `functions` map dispatches by name, and the helpers only these use. Each reads its members
// as api/keys.rs does, in its order.

import "encoding/json"

func callGenerateKey(a args) json.RawMessage {
	alg, err := a.str("alg")
	if err != nil {
		return failAs(codeArgs, err)
	}
	priv, err := GenerateKey(alg)
	if err != nil {
		return failErr("unsupported", err)
	}
	o, err := keyOut(priv)
	if err != nil {
		return failAs("parse", err)
	}
	return ok(o)
}

// §2.1. Two calls rather than one so a wallet never hardcodes the salt: the constant lives here,
// the vectors prove it, and a caller that gets it wrong fails loudly instead of quietly becoming
// somebody else.
func callPrfSalt(args) json.RawMessage {
	return ok(map[string]any{"salt": B64(PrfSalt()), "infos": DerivationInfos})
}

func callDeriveSeed(a args) json.RawMessage {
	prf, err := a.bytes("prf")
	if err != nil {
		return failAs(codeArgs, err)
	}
	info, err := a.str("info")
	if err != nil {
		return failAs(codeArgs, err)
	}
	seed, err := DeriveSeed(prf, info)
	if err != nil {
		return failErr(codeArgs, err)
	}
	return ok(map[string]any{"seed": B64(seed)})
}

// key_from_seed reads `alg` first, as CONTRACT §1 lists it: the algorithm, then the seed that is
// read for it (T21's direction; the core read the seed's length first). A seed that is not a string
// is `seed is required`, as the core reads it.
func callKeyFromSeed(a args) json.RawMessage {
	alg, err := a.str("alg")
	if err != nil {
		return failAs(codeArgs, err)
	}
	if err := algKnown(alg); err != nil {
		return failAs(codeArgs, err)
	}
	if _, isText := a.text("seed"); !isText {
		return fail(codeArgs, "seed is required")
	}
	seed, err := a.seed32("seed")
	if err != nil {
		return failAs("parse", err)
	}
	priv, err := KeyFromSeed(alg, seed)
	if err != nil {
		return failAs("parse", err)
	}
	o, err := keyOut(priv)
	if err != nil {
		return failAs("parse", err)
	}
	return ok(o)
}

func callPublicKey(a args) json.RawMessage {
	priv, err := a.priv("pkcs8")
	if err != nil {
		return failAs("parse", err)
	}
	pub := priv.Public()
	return ok(map[string]any{"alg": priv.Alg, "spki": B64url(pub.SPKI), "fingerprint": Fingerprint(pub.SPKI)})
}

func callKeyInfo(a args) json.RawMessage {
	pub, err := a.pub("spki")
	if err != nil {
		return failAs("parse", err)
	}
	return ok(map[string]any{"alg": pub.Alg, "fingerprint": Fingerprint(pub.SPKI), "key_id": B64url(KeyID(pub.SPKI))})
}

func callSign(a args) json.RawMessage {
	priv, err := a.priv("pkcs8")
	if err != nil {
		return failAs("parse", err)
	}
	data, err := a.bytes("data")
	if err != nil {
		return failAs(codeArgs, err)
	}
	sig, err := SignDetached(priv, data)
	if err != nil {
		return failAs("parse", err)
	}
	return ok(map[string]any{"sig": B64url(sig)})
}

func callVerify(a args) json.RawMessage {
	pub, err := a.pub("spki")
	if err != nil {
		return failAs("parse", err)
	}
	data, err := a.bytes("data")
	if err != nil {
		return failAs(codeArgs, err)
	}
	sig, err := a.bytes("sig")
	if err != nil {
		return failAs(codeArgs, err)
	}
	return ok(map[string]any{"valid": VerifyDetached(pub, data, sig)})
}

func keyOut(priv *PrivateKey) (map[string]any, error) {
	pkcs8, err := priv.PKCS8()
	if err != nil {
		return nil, err
	}
	pub := priv.Public()
	return map[string]any{"alg": priv.Alg, "pkcs8": B64url(pkcs8), "spki": B64url(pub.SPKI), "fingerprint": Fingerprint(pub.SPKI)}, nil
}
