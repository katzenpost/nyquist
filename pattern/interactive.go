// Copryright (C) 2019 Yawning Angel
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package pattern

var (
	// NN is the NN interactive (fundemental) pattern.
	NN Pattern = &builtIn{
		name: "NN",
		messages: []Message{
			Message{Token_e},
			Message{Token_e, Token_ee},
		},
	}

	// NK is the NK interactive (fundemental) pattern.
	NK Pattern = &builtIn{
		name: "NK",
		preMessages: []Message{
			nil,
			Message{Token_s},
		},
		messages: []Message{
			Message{Token_e, Token_es},
			Message{Token_e, Token_ee},
		},
	}

	// NX is the NX interactive (fundemental) pattern.
	NX Pattern = &builtIn{
		name: "NX",
		messages: []Message{
			Message{Token_e},
			Message{Token_e, Token_ee, Token_s, Token_es},
		},
	}

	// XN is the XN interactive (fundemental) pattern.
	XN Pattern = &builtIn{
		name: "XN",
		messages: []Message{
			Message{Token_e},
			Message{Token_e, Token_ee},
			Message{Token_s, Token_se},
		},
	}

	// XK is the XK interactive (fundemental) pattern.
	XK Pattern = &builtIn{
		name: "XK",
		preMessages: []Message{
			nil,
			Message{Token_s},
		},
		messages: []Message{
			Message{Token_e, Token_es},
			Message{Token_e, Token_ee},
			Message{Token_s, Token_se},
		},
	}

	// XX is the XX interactive (fundemental) pattern.
	XX Pattern = &builtIn{
		name: "XX",
		messages: []Message{
			Message{Token_e},
			Message{Token_e, Token_ee, Token_s, Token_es},
			Message{Token_s, Token_se},
		},
	}

	// KN is the KN interactive (fundemental) pattern.
	KN Pattern = &builtIn{
		name: "KN",
		preMessages: []Message{
			Message{Token_s},
		},
		messages: []Message{
			Message{Token_e},
			Message{Token_e, Token_ee, Token_se},
		},
	}

	// KK is the KK interactive (fundemental) pattern.
	KK Pattern = &builtIn{
		name: "KK",
		preMessages: []Message{
			Message{Token_s},
			Message{Token_s},
		},
		messages: []Message{
			Message{Token_e, Token_es, Token_ss},
			Message{Token_e, Token_ee, Token_se},
		},
	}

	// KX is the KX interactive (fundemental) pattern.
	KX Pattern = &builtIn{
		name: "KX",
		preMessages: []Message{
			Message{Token_s},
		},
		messages: []Message{
			Message{Token_e},
			Message{Token_e, Token_ee, Token_se, Token_s, Token_es},
		},
	}

	// IN is the IN interactive (fundemental) pattern.
	IN Pattern = &builtIn{
		name: "IN",
		messages: []Message{
			Message{Token_e, Token_s},
			Message{Token_e, Token_ee, Token_se},
		},
	}

	// IK is the IK interactive (fundemental) pattern.
	IK Pattern = &builtIn{
		name: "IK",
		preMessages: []Message{
			nil,
			Message{Token_s},
		},
		messages: []Message{
			Message{Token_e, Token_es, Token_s, Token_ss},
			Message{Token_e, Token_ee, Token_se},
		},
	}

	// IX is the IX interactive (fundemental) pattern.
	IX Pattern = &builtIn{
		name: "IX",
		messages: []Message{
			Message{Token_e, Token_s},
			Message{Token_e, Token_ee, Token_se, Token_s, Token_es},
		},
	}

	// NNpsk0 is the NNpsk0 interactive (fundemental) pattern.
	NNpsk0 Pattern = &builtIn{
		name: "NNpsk0",
		messages: []Message{
			Message{Token_psk, Token_e},
			Message{Token_e, Token_ee},
		},
		numPSKs: 1,
	}

	// NNpsk2 is the NNpsk2 interactive (fundemental) pattern.
	NNpsk2 Pattern = &builtIn{
		name: "NNpsk2",
		messages: []Message{
			Message{Token_e},
			Message{Token_e, Token_ee, Token_psk},
		},
		numPSKs: 1,
	}

	// NKpsk0 is the NKpsk0 interactive (fundemental) pattern.
	NKpsk0 Pattern = &builtIn{
		name: "NKpsk0",
		preMessages: []Message{
			nil,
			Message{Token_s},
		},
		messages: []Message{
			Message{Token_psk, Token_e, Token_es},
			Message{Token_e, Token_ee},
		},
		numPSKs: 1,
	}

	// NKpsk2 is the NKpsk2 interactive (fundemental) pattern.
	NKpsk2 Pattern = &builtIn{
		name: "NKpsk2",
		preMessages: []Message{
			nil,
			Message{Token_s},
		},
		messages: []Message{
			Message{Token_e, Token_es},
			Message{Token_e, Token_ee, Token_psk},
		},
		numPSKs: 1,
	}

	// NXpsk2 is the NXpsk2 interactive (fundemental) pattern.
	NXpsk2 Pattern = &builtIn{
		name: "NXpsk2",
		messages: []Message{
			Message{Token_e},
			Message{Token_e, Token_ee, Token_s, Token_es, Token_psk},
		},
		numPSKs: 1,
	}

	// XNpsk3 is the XNpsk3 interactive (fundemental) pattern.
	XNpsk3 Pattern = &builtIn{
		name: "XNpsk3",
		messages: []Message{
			Message{Token_e},
			Message{Token_e, Token_ee},
			Message{Token_s, Token_se, Token_psk},
		},
		numPSKs: 1,
	}

	// XKpsk3 is the XKpsk3 interactive (fundemental) pattern.
	XKpsk3 Pattern = &builtIn{
		name: "XKpsk3",
		preMessages: []Message{
			nil,
			Message{Token_s},
		},
		messages: []Message{
			Message{Token_e, Token_es},
			Message{Token_e, Token_ee},
			Message{Token_s, Token_se, Token_psk},
		},
		numPSKs: 1,
	}

	// XXpsk3 is the XXpsk3 interactive (fundemental) pattern.
	XXpsk3 Pattern = &builtIn{
		name: "XXpsk3",
		messages: []Message{
			Message{Token_e},
			Message{Token_e, Token_ee, Token_s, Token_es},
			Message{Token_s, Token_se, Token_psk},
		},
		numPSKs: 1,
	}

	// KNpsk0 is the KNpsk0 interactive (fundemental) pattern.
	KNpsk0 Pattern = &builtIn{
		name: "KNpsk0",
		preMessages: []Message{
			Message{Token_s},
		},
		messages: []Message{
			Message{Token_psk, Token_e},
			Message{Token_e, Token_ee, Token_se},
		},
		numPSKs: 1,
	}

	// KNpsk2 is the KNpsk2 interactive (fundemental) pattern.
	KNpsk2 Pattern = &builtIn{
		name: "KNpsk2",
		preMessages: []Message{
			Message{Token_s},
		},
		messages: []Message{
			Message{Token_e},
			Message{Token_e, Token_ee, Token_se, Token_psk},
		},
		numPSKs: 1,
	}

	// KKpsk0 is the KKpsk0 interactive (fundemental) pattern.
	KKpsk0 Pattern = &builtIn{
		name: "KKpsk0",
		preMessages: []Message{
			Message{Token_s},
			Message{Token_s},
		},
		messages: []Message{
			Message{Token_psk, Token_e, Token_es, Token_ss},
			Message{Token_e, Token_ee, Token_se},
		},
		numPSKs: 1,
	}

	// KKpsk2 is the KKpsk2 interactive (fundemental) pattern.
	KKpsk2 Pattern = &builtIn{
		name: "KKpsk2",
		preMessages: []Message{
			Message{Token_s},
			Message{Token_s},
		},
		messages: []Message{
			Message{Token_e, Token_es, Token_ss},
			Message{Token_e, Token_ee, Token_se, Token_psk},
		},
		numPSKs: 1,
	}

	// KXpsk2 is the KXpsk2 interactive (fundemental) pattern.
	KXpsk2 Pattern = &builtIn{
		name: "KXpsk2",
		preMessages: []Message{
			Message{Token_s},
		},
		messages: []Message{
			Message{Token_e},
			Message{Token_e, Token_ee, Token_se, Token_s, Token_es, Token_psk},
		},
		numPSKs: 1,
	}

	// INpsk1 is the INpsk1 interactive (fundemental) pattern.
	INpsk1 Pattern = &builtIn{
		name: "INpsk1",
		messages: []Message{
			Message{Token_e, Token_s, Token_psk},
			Message{Token_e, Token_ee, Token_se},
		},
		numPSKs: 1,
	}

	// INpsk2 is the INpsk2 interactive (fundemental) pattern.
	INpsk2 Pattern = &builtIn{
		name: "INpsk2",
		messages: []Message{
			Message{Token_e, Token_s},
			Message{Token_e, Token_ee, Token_se, Token_psk},
		},
		numPSKs: 1,
	}

	// IKpsk1 is the IKpsk1 interactive (fundemental) pattern.
	IKpsk1 Pattern = &builtIn{
		name: "IKpsk1",
		preMessages: []Message{
			nil,
			Message{Token_s},
		},
		messages: []Message{
			Message{Token_e, Token_es, Token_s, Token_ss, Token_psk},
			Message{Token_e, Token_ee, Token_se},
		},
		numPSKs: 1,
	}

	// IKpsk2 is the IKpsk2 interactive (fundemental) pattern.
	IKpsk2 Pattern = &builtIn{
		name: "IKpsk2",
		preMessages: []Message{
			nil,
			Message{Token_s},
		},
		messages: []Message{
			Message{Token_e, Token_es, Token_s, Token_ss},
			Message{Token_e, Token_ee, Token_se, Token_psk},
		},
		numPSKs: 1,
	}

	// IXpsk2 is the IXpsk2 interactive (fundemental) pattern.
	IXpsk2 Pattern = &builtIn{
		name: "IXpsk2",
		messages: []Message{
			Message{Token_e, Token_s},
			Message{Token_e, Token_ee, Token_se, Token_s, Token_es, Token_psk},
		},
		numPSKs: 1,
	}
)
