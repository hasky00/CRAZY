ObjectInputStream in = new ObjectInputStream(sock.getInputStream());
stmt.executeQuery("SELECT * FROM tx WHERE id=" + id);
Random r = new Random();
