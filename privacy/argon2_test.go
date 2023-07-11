package privacy

import (
	"crypto/rand"
	"encoding/json"
	"reflect"
	"testing"
)

func TestNewArgon2(t *testing.T) {
	k := NewArgon2()
	if _, ok := k.(argon2Params); !ok {
		t.Fatal("unexpected")
	}
}

func TestNewArgon2WithParams(t *testing.T) {
	type args struct {
		time    uint32
		memory  uint32
		threads uint8
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "positive",
			args: args{
				time:    1,
				memory:  4 * 1024,
				threads: 4,
			},
			wantErr: false,
		},
		{
			name: "negative: zero time",
			args: args{
				time:    0,
				memory:  1 * 1024,
				threads: 4,
			},
			wantErr: true,
		},
		{
			name: "negative: zero memory",
			args: args{
				time:    1,
				memory:  0,
				threads: 4,
			},
			wantErr: true,
		},
		{
			name: "negative: zero threads",
			args: args{
				time:    1,
				memory:  1 * 1024,
				threads: 0,
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewArgon2WithParams(tt.args.time, tt.args.memory, tt.args.threads)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewArgon2WithParams() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func TestArgon2Params_MarshalJSON(t *testing.T) {
	var (
		b   []byte
		err error
		str string
		ok  bool
		a   any
	)

	if b, err = NewArgon2().MarshalJSON(); err != nil {
		t.Fatal("unexpected", err)
	}

	m := make(map[string]any)
	if err = json.Unmarshal(b, &m); err != nil {
		t.Fatal("unexpected", err)
	}

	if a, ok = m["name"]; !ok {
		t.Fatal("unexpected: no field name")
	}

	if str, ok = a.(string); !ok {
		t.Fatal("unexpected: name field is not a string")
	}

	if str != argon2KeyGenName {
		t.Fatal("unexpected: value of the name")
	}
}

func Test_argon2Params_GenerateKey(t *testing.T) {
	type fields struct {
		Time    uint32
		Memory  uint32
		Threads uint8
		Name    string
	}
	type args struct {
		password []byte
		salt     []byte
	}

	var (
		prepKG  KeyGen
		prepErr error
	)

	passphrase := "some passphrase"
	salt := make([]byte, 16)
	if _, prepErr = rand.Read(salt); prepErr != nil {
		t.Fatal("test preparation failure:", prepErr)
	}

	if prepKG, prepErr = NewArgon2WithParams(1, 1*1024, 2); prepErr != nil {
		t.Fatal("test preparation failure:", prepErr)
	}
	prepBytes := prepKG.GenerateKey([]byte(passphrase), salt)

	tests := []struct {
		name   string
		fields fields
		args   args
		want   []byte
	}{
		{
			name: "positive",
			fields: fields{
				Time:    1,
				Memory:  1 * 1024,
				Threads: 2,
				Name:    argon2KeyGenName,
			},
			args: args{
				password: []byte(passphrase),
				salt:     salt,
			},
			want: prepBytes,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := argon2Params{
				Time:    tt.fields.Time,
				Memory:  tt.fields.Memory,
				Threads: tt.fields.Threads,
				Name:    tt.fields.Name,
			}
			if got := a.GenerateKey(tt.args.password, tt.args.salt); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("GenerateKey() = %v, want %v", got, tt.want)
			}
		})
	}
}
