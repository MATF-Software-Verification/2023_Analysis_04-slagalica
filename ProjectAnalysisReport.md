# Izveštaj analize projekta

## Tehnički uvod

Projekat <b>Slagalica</b> sastoji se od 4 podprojekta:
 * <b>serialization</b> - biblioteka za JSON serijalizaciju i deserijalizaciju
 * <b>server</b> - serverska aplikacija zadužena za očitavanje kombinacija pitanja iz skupa mogućih kombinacija i bodovanje takmičara
 * <b>slagalica</b> - klijentska GUI aplikacija, uspostavlja TCP konekciju sa serverom
 * <b>tests</b> - testovi jedinice koda implementirana u Catch2 biblioteci (Catch 2.13.7 verzija) 

Alat <b>qmake</b> pomaže da se pojednostavi proces izgradnje koda projekata na različitim platformama. Ovaj alat automatizuje generisanje Makefile-a tako da je potrebno samo nekoliko redova informacija za kreiranje svakog Makefile-a. Može se koristiti za bilo koji softverski projekat, bilo da koristi Qt razvojni okvir ili ne. Qmake generiše Makefile na osnovu informacija u <b>.pro</b> datoteci projekta. Ove datoteke kreira programer i obično su jednostavne i lako razumljive, ali za složene projekte mogu se kreirati kompleksniji projektni fajlovi.
U projektnom fajlu analiziranog projekta specifikovano je da je šablon (eng. *template*) <b>subdirs</b>. Osnovna ideja ovog tipa šablona je da navede sve podprojekte koji pripadaju nekoj vrsti meta projekta. Datoteka kreirana za meta projekat (**game.pro**) sastoji se samo od qmake sistemske promenljive SUBDIRS kojoj se dodeljuju relativne putanje do direktorijuma gde se nalazi .pro datoteka svakog od podprojekata (**serialization.pro**, **server.pro**, **slagalica.pro**, **tests.pro**). Uz projekat dostupna je detaljna UML specifikacija koja može biti korisna za bolje razumevanje unutrašnje strukture koda. 

Pritiskom na *Build* opciju u donjem levom uglu ekrana dolazi do problema zbog redosleda izgradnje podprojekata i njihovih međuzavisnosti:
![img](qmake/problem.png)

Izvršni fajlovi zahtevaju biblioteku za serijalizaciju stoga ona mora biti prva prevedena. Na qmake sistemsku promenljivu CONFIG dodajemo opciju da se podprojekti *build*-uju u navedenom redosledu.
Treba imati na umu da se ovakvo rešenje smatra prevaziđenim i nije primenjivo za složenije modele zavisnosti.
![img](qmake/resenje.png)

Nakon ove izmene u **game.pro** datoteci projekat se prevodi. Sada možemo pokrenuti server i dva klijenta i započeti kviz.
![img](qmake/pokretanjeigre.png)

Takođe, možemo pokrenuti testove i uveriti se da svi napisani *unit* testovi prolaze. Više reči o testovima biće u narednom odeljku.
![img](qmake/pokretanjetestova.png)

Skripta za prevođenje i pokretanje jedne partije (server i dva klijenta): [start_game.sh](https://github.com/MATF-Software-Verification/2023_Analysis_04-slagalica/blob/main/qmake/skripte/start_game.sh) \
Skripta za prevođenje i pokretanje testove: [start_testing.sh](https://github.com/MATF-Software-Verification/2023_Analysis_04-slagalica/blob/main/qmake/skripte/start_testing.sh)





