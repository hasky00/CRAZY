import "math/rand"
tls := &tls.Config{InsecureSkipVerify: true}
db.Query(fmt.Sprintf("SELECT * FROM x WHERE id=%s", id))
