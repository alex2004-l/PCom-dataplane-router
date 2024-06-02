## Tema Protocoale de Comunicatii - Dataplane Router
---
#### Tema realizata de Lache Alexandra FLorentina Georgiana, 321CDb, An universitar 2023-2024
---

Am pornit de la scheletul laboratorului 4. 
Alte surse auxiliare : https://www.geeksforgeeks.org/longest-common-prefix-using-trie/, https://www.imperva.com/learn/performance/time-to-live-ttl/#:~:text=The%20common%20default%20TTL%20values,255%20%E2%80%93%20Network%20devices%20like%20routers.

---

Implementare IPv4

- Dupa ce se verifica ca pachetul este pentru router, ca tipul protocolului construit peste headerul de Ethernet este IPv4 si ca dimensiunea pachetului este mai mare sau egala decat dimensiunea minima necesara(simensiunea de header ethernet + dimensiunea de header ip), se verifica ca pachetul sa nu fie corupt, recalculand checksum-ul pentru datele primite si comparandu-l cu vechiul checksum-ul pentru datele trimise. Daca nu se potrivesc, pachetul este dropped. Ca mecanism pentru a verifica ca pachetul nu cicleaza, se decrementeaza TTL-ul pachetului, iar in cazul in care valoarea devine <= 1, se da drop la pachet.
- Se obtine cea mai buna ruta in functie de ip-ul destinatiei, iar in cazul in care nu exista vreo ruta, se da drop la pachet. Algoritmul de LPM se foloseste de o trie, construita in functie de prefixul si lungimea mastii pentru fiecare intrare din tabela de rutare. Lungimea "cuvintelor" adaugate in trie este pentru fiecare intrare aceeasi cu lungimea mastii, iar in functie de bitii setati din prefix, se adauga/parcurg noduri in trie(0 - bitul nu e setat, se adauga copil stang, 1 - bitul este setat, se adauga copil drept).
- Se updateaza adresele mac din headerul Ethernet; adresa destinatiei este adresa la care se afla next_hop (in cazul tabelei dinamice, daca nu exista, se trimite cerere si pachetul e bagat in coada).
- Se trimite pachetul modificat pe interfata hopului urmator.

---

Implementare ARP

- Routerul trebuie sa trimita un ARP request pentru a afla adresa MAC urmatorului hop unde trebuie sa trimita pachetul: se pune pachetul care trebuie trimis intr-o coada, si se construieste un nou pachet(functia `send_arp_request()`), unde field-urile asociate sursei corespund interfetei routerului pe care se trimite cererea, iar field-urile asociate adresei mac a destinatiei sunt setate pe broadcast. Din moment ce este un pachet ARP de tip request, codul din headerul ARP este setat pe 1.
- Routerul primeste un ARP request si trebuie sa trimita un ARP reply din care sa reiasa adresa lui mac(functia `parse_arp_request`): se actualizeaza campurile din header-urile Ethernet si ARP, si se trimite pachetul inapoi pe interfata de unde s-a primit, avand mac-ul si ip-ul sursei corespunzatoare acelei interfete a routerului.
- Routerul primeste un ARP reply la un request pe care l-a trimis(`parse_arp_reply`): adauga in cache-ul ARP perechea formata din ip-ul si mac-ul sursei, si dupa, daca coada nu este goala, scoate pachetul, ii actualizeaza valoarea adresei mac pentru destinatie din header-ul Ethernet, si il trimite pe interfata corespunzatoare urmatorului hop.

---

Implementare ICMP

- Echo request: Daca deasupra protocolului IPv4 in pachetul primit se afla protocolul ICMP, iar codul pentru tipul mesajului este 8, routerul trimite un pachet ICMP reply catre sursa pachetului primit (se inverseaza valorile imtre campurile corespunzatoare surselor si destinatiilor, se reseteaza TTL-ul pentru a fi siguri ca pachetul se intoarce la sursa, se calculeaza checksum-ul pentru header-ul IP si pentru header-ul ICMP - checksumul din headerul IP corespunde doar valorilor din header, in timp ce cel din headerul ICMP este calculat pentru datele din header + payload).
- Echo error message: In cazul in care se da drop la un pachet, routerul ii trimite sursei pachetului un pachet ICMP cu codul aferent erorii intalnite, si un payload cu headeru ip + primii 64 biti din pachetul care a fost dropped.

---
