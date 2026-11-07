Darie Vlad-Andrei - 321CC

1. Forwarding
    In poza subiect1.png am trimis un ping de la h-0 la h-1.
    Pentru ca h-0 nu stie adresa MAC a routerului, acesta trimite un ARP request (pachetul 1)
cu destinatia broadcast. In pachetul 2 este un ARP reply de la router cu adresa lui MAC.
    Urmeaza pachetul 3 care e un ICMP echo request de la h-0 la h-1 cu un TTL de 64.
    Routerul primeste pachetul 3, scade TTL ul la 63 si cauta in route table pentru a gasi cea
mai buna ruta pentru adresa IP a destinatiei (h-1). Pt ca nu are adresa MAC a lui h-1, retine
retine pachetul 3 si trimite un ARP request (pachetul 4) cu destinatia broadcast pentru a afla
adresa MAC a lui h-1.
    Dupa ce primeste ARP reply ul de la h-1 (pachetul 5), routerul trimite pachetul 3 catre h-1
(pachetul 6) folosind adresa MAC a lui h-1 ca destinatie. Dupa ce h-1 primeste pachetul 6, acesta
trimite un ICMP echo reply (pachetul 7) catre h-0 cu TTL 64. Pachetul 7 trece prin router, care nu
stie adresa MAC a lui h-0, asa ca retine pachetul 7 si trimite un ARP request (pachetul 8) cu
destinatia broadcast pentru a afla adresa MAC a lui h-0. Dupa ce primeste ARP reply ul de la
h-0 (pachetul 9), routerul trimite pachetul 7 catre h-0 (pachetul 10).
    Ultimele 2 pachete sunt un ARP request si un ARP reply trimise la 5 sec distanta de pachetul 10
pentru a actualiza cache ul ARP ului.

2. LPM
    Pentru a cauta LPM am folosit o structura de date Trie cu noduri care contin un vector de 2
copii (pt bitul 0 si pt bitul 1) si un pointer catre o adresa IP din route table (doar daca nodul
respectiv reprezinta o ruta valida).
    Pentru a construi Trie ul am parcurs fiecare ruta din route table, am transformat adresa IP in
host order si am adaugat o in Trie, adaugand noduri pentru fiecare bit din adresa IP pana la lungimea
prefixului. Daca am ajuns la lungimea prefixului, am setat pointerul catre adresa IP din route table.
    Pentru a cauta LPM pentru o adresa IP data, am parcurs Trie ul incepand de la radacina, pe calea
corespunzatoare bitilor din adresa IP. Daca am gasit un nod care reprezinta o ruta valida, am retinut
adresa IP corespunzatoare. Am continuat sa parcurg Trie ul pana cand nu mai puteam continua sau am
ajuns la un nod care nu reprezinta o ruta valida. La final, am returnat adresa IP retinuta ca fiind
LPM pentru adresa IP data.
    Aceasta metoda de implementare a LPM e eficienta pt ca Trie ul are o adancime maxima de 32
(lungimea maxima a unui prefix), iar cautarea LPM se face cu o complexitate constanta de O(32)
in cel mai rau caz, fata de o cautare liniara in route table care ar avea o complexitate de O(n),
in care n = nr de rute din route table.

3. Protocolul ARP
    In poza subiect3 (1).png am trimis un arping de la h-0 la router pentru a afla adresa MAC a
routerului.
    In poza subiect3 (2).png am trimis 2 ping uri de la h-0 la h-1 pentru a arata existenta
cache ului ARP.
    In prima poza, h-0 trimite un ARP request (pachetul 1) cu destinatia broadcast pentru a afla
adresa MAC a routerului. Routerul primeste pachetul si trimite inapoi un ARP reply (pachetul 2) spre
h-0 cu adresa MAC a sa.
    In a doua poza, primele 12 pachete sunt aceleasi ca in poza subiect1.png si explicate mai sus
la 1. Forwarding. Ultimele 4 pachete reprezinta un nou ping de la h-0 la h-1 dar de data asta fara
nici un ARP request sau ARP reply, ceea ce arata ca adresa MAC au fost retinute in cache ARP.

4. Protocolul ICMP
    In poza subiect4 (1).png am trimis un ping de la h-0 la h-1 cu TTL 1 pentru a arata cum
functioneaza ICMP err Time Exceeded.
    In poza subiect4 (2).png am trimis un ping de la h-0 la o adresa IP care nu exista in
route table pentru a arata cum functioneaza ICMP err Destination Unreachable.
    In prima poza, h-0 trimite un ICMP echo request (pachetul 1) cu TTL 1 catre h-1. Routerul
primeste pachetul, scade TTL ul la 0 si trimite inapoi un ICMP err Time Exceeded (pachetul 2)
catre h-0. Ultimele 2 pachete sunt un ARP request si un ARP reply trimise la 5 sec distanta de
pachetul 2 pentru a actualiza cache ul ARP ului.
    In a doua poza, h-0 trimite un ICMP echo request (pachetul 1) catre o adresa IP care nu
exista in route table. Routerul primeste pachetul, nu gaseste o ruta pentru adresa IP a
destinatiei si trimite inapoi un ICMP err Destination Unreachable (pachetul 2) catre h-0.
Ultimele 2 pachete sunt un ARP request si un ARP reply trimise la 5 sec distanta de pachetul 2
pentru a actualiza cache ul ARP ului.