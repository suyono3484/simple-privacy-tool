package privacy

import "testing"

func TestTrial(t *testing.T) {
	x := make([]byte, 20)
	for i := range x {
		x[i] = byte(i)
	}

	t.Log("len x:", len(x))
	t.Log("cap x:", cap(x))
	t.Log("x:", x)

	y := x[5:13]
	t.Log("len y:", len(y))
	t.Log("cap y:", cap(y))
	t.Log("y:", y)

	z := y[10:15]
	t.Log("len z:", len(z))
	t.Log("cap z:", cap(z))
	t.Log("z:", z)
}
