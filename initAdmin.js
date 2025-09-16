import sqlite3 from 'sqlite3';
import bcrypt from 'bcrypt';

const db = new sqlite3.Database('./db/database.sqlite');

const email = 'info@battagliaracingcar.com';
const password = 'Prova1234!';
const role = 'admin';

bcrypt.hash(password, 10, (err, hash) => {
  if (err) {
    console.error('Errore durante l\'hash della password:', err);
    return;
  }

  db.run(
    'INSERT INTO users (email, password, role) VALUES (?, ?, ?)',
    [email, hash, role],
    (err) => {
      if (err) {
        console.error('Errore durante la creazione dell\'utente admin:', err.message);
      } else {
        console.log('✅ Utente admin creato correttamente!');
      }
      db.close();
    }
  );
});
