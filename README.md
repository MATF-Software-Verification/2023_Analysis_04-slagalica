# 2023_Analysis_04-slagalica

## :memo:  Informacije o projektu:

* U okviru ovog rada predstavljena je analiza projekta <b>Slagalica</b> rađenog za potrebe kursa Razvoj softvera na Matematičkom fakultetu. Projekat se nalazi na adresi https://gitlab.com/matf-bg-ac-rs/course-rs/projects-2022-2023/04-slagalica, 
analiza je vršena nad main granom projekta i to nad commit-om čiji je heš kod d4b71df08986f678ee8187e064f0d7c0447e08ac. Opisan je postupak primene različitih alata i tehnika za verifikaciju softvera, dobijeni rezultati, pronađeni bagovi i uska grla kao i potencijalni pravci unapređenja kvaliteta analiziranog projekta.

* Projekat <b>Slagalica</b> je kviz igrica napravljena po ugledu na popularni TV kviz u kome se dva igrača takmiče ko će osvojiti više poena u različitim igrama. Jedna partija sastoji se od 4 implementirane igre: Skočko, Ko zna zna, Spojnice i Asocijacije. Za implementaciju je korišćen programski jezik <b>C++</b> (C++17) i razvojni okvir <b>Qt 6</b> - za analizu korišćena najnovija stabilna verzija Qt 6.6.1. Neophodno je instalirati dodatne biblioteke Qt Multimedia i Qt Multimedia Widgets korišćnjem Qt Maintenance Tool-a. Detaljniji opis i tehničke informacije o preuzimanju i pokretaju, kao i demo snimak, mogu se pronaći u README.md fajlu projekta. Na pomenutom snimku autori detaljno pojašnjavanju pravila i sistem bodovanja kviza.    

## :hammer: :wrench: Primenjeni alati/tehnike:
Spisak korišćenih alata i tehnika za verifikaciju softvera:
  - **Gcov** - analiza pokrivenosti koda postojećim testovima jedinica koda
  - **Clang alati**:
    - **Clang-Tidy**
    - **Clazy**
    - **Clang-Format**
  
Za svaki od navedenih alata postoji direktorijum u kome se nalaze rezultati i skripta za pokretanje odgovarajućeg alata. 

## :memo: Rezultati i zaključci:

:mag: Detaljan opis analize projekta i izvedenih zaključaka nalazi se u [ProjectAnalysisReport.md](https://github.com/MATF-Software-Verification/2023_Analysis_04-slagalica/blob/main/ProjectAnalysisReport.md) fajlu.

## :man_technologist:  Autor:
<b>Pavle Savić, 1075/2022</b>
