---
title: "Incident analysis based on MITRE standards"
author: "Daniel Pulido"
date: "20/01/2021"
output:
  html_document: default
  pdf_document: default
---

```{r setup, include=FALSE}
knitr::opts_chunk$set(echo = TRUE)
if (!dir.exists("data")) dir.create("data")
if (!dir.exists("data-raw")) dir.create("data-raw")
```


```{r load_packages, echo=FALSE}
suppressPackageStartupMessages(library("dplyr"))
library("tidyr")
library("DataExplorer")
library("ggridges")
library("ggplot2")
library("hrbrthemes")
library("viridisLite")
library("viridis")
library("kableExtra")
```

```{r install_mitre, echo=FALSE}
# devtools::install_github(repo = "motherhack3r/mitre", ref = "devel")
library(mitre)
```

# Introducción

Como miembros del CADET (Cybersecurity Analyst Data Experts Team) se solicita 
vuestra colaboración para el análisis de los incidentes que afectaron con anterioridad.

![Especialidades individuales](images/cadet.png)


## Objetivo

El objetivo consiste en responder las siguientes preguntas:

  1. ¿Quien estaba detras de los ataques?
  2. ¿Cual fue el objetivo?
  3. ¿Cómo realizaron los ataques?
  4. ¿Cómo podemos protegernos?
  5. ¿Qué podemos hacer para prevenir futuros ataques?
  6. ¿Sería posible predecir ataques?

## Alcance

Respondiendo 3 preguntas se consigue una puntuación de 5 sobre 10.  
Las siguientes preguntas suman 2 puntos, pudiendo conseguir un máximo de 10.

# Data sets

```{r mitre_download_feeds, cache=TRUE, echo=FALSE, warning=FALSE, results='hide'}
mitre::updateRawData(verbose = FALSE)
```

```{r mitre_create_datasets, cache=TRUE, echo=FALSE, warning=FALSE, results='hide'}
#mitre.data <- mitre::getMitreNetwork(verbose = F)
mitre.data <- mitre::getLatestDataSet()
```

## Incidentes

Load incidents data set and unnest ATT&CK column.

```{r ds_incidents}
raw_incidents <- readRDS(file = "data/incidents.rds")
incidents <- raw_incidents %>% unnest(mitre_attack)
summary(incidents)
```
Analyze character columns to identify unique values.

```{r ds_inc_factors}
apply(incidents, 2, function(x) length(unique(x)))
```

Set character columns as factor.

```{r}
incidents <- incidents %>%
  mutate_if(is.character, as.factor)
summary(incidents)
```
```{r fig.width=8, fig.height=8}
plot_correlation(incidents)
```

Seems that Tactic and Industry values are interesting.
Let's see industry distribution along time.

```{r, warning=FALSE}
# Ref: https://www.r-graph-gallery.com/294-basic-ridgeline-plot.html

ggplot(incidents, aes(x = first_event_ts, y = industry, fill = industry)) +
  geom_density_ridges() +
  theme_ridges() + 
  theme(legend.position = "none")

```
  
The time series distribution is based on first event. We can calculate the duration of the incidents using containment time.

```{r fig.width=8, fig.height=8, warning=FALSE}
# Ref: https://www.r-graph-gallery.com/320-the-basis-of-bubble-plot.html
incidents <- incidents %>% mutate(duration = round(as.numeric(containment_ts - first_event_ts)/3600, 2))

incidents %>%
  arrange(desc(first_event_ts)) %>%
  # mutate(country = factor(country, country)) %>%
  ggplot(aes(x=first_event_ts, y=industry, size=duration, fill=tactic)) +
  geom_point(alpha=0.5, shape=21, color="black") +
  scale_size(range = c(.1, 20), name="Duration") +
    scale_fill_viridis(discrete=TRUE, guide=FALSE, option="A") +
    theme_ipsum() +
    theme(legend.position="bottom") +
    ylab("Industry") +
    xlab("Incidents") +
    theme(legend.position = "none")
```


## CVE

__TODO__

```{r ds_cve}
raw_cves <- mitre.data$standards$cve
```

## CWE

__TODO__

```{r ds_cwe}
raw_cwes <- mitre.data$standards$cwe
```

## ATT&CK

__TODO__

```{r ds_attck}
raw_attck <- mitre.data$standards$attck
```

## SHIELD

__TODO__

```{r ds_shield}
raw_shield <- mitre.data$standards$shield
```

## CPE

__TODO__

```{r ds_cpe}
raw_cpes <- mitre.data$standards$cpe
```


## CAR

__TODO__

```{r ds_car}
raw_car <- mitre.data$standards$car
```

## CAPEC

__TODO__

```{r ds_capec}
raw_capec <- mitre.data$standards$capec
```

# 1. Empieza la exploración en incidents

## 1.1 Incidents 
Obtenemos los incidentes no repetidos, extraemos el campo id y lo transformamos en formato caracter.
Finalmente, vemos los identificadores por ocurrencia. 
```{r incidents}
inc_unique <- unique(incidents)
inc_id_tech <- as.character(inc_unique$id)
sort(table(inc_id_tech))
```

## 1.2 CAR
Comparamos las techniques de incidents con las techniques relacionadas de CAR y obtenemos la relación.
```{r }
#which(inc_id_tech %in% raw_car$carnet$edges$to)
inc_tech_car <- inc_id_tech[which(inc_id_tech %in% raw_car$carnet$edges$to)]
```

Relacionamos las techniques encontradas en CAR con la de todos los estandares.
```{r }
car_mitre_from <- which(mitre.data$mitrenet$edges$from %in% inc_tech_car)
car_mitre_to <- which(mitre.data$mitrenet$edges$to %in% inc_tech_car)
```

Probamos una posición encontrada tanto en el campo from, en el to y en la relación completa.
```{r }
mitre.data$mitrenet$edges$from[10588]
mitre.data$mitrenet$edges$to[10588]
mitre.data$mitrenet$edges[10588,]
```

Ahora buscamos todas las coincidencias de los estandares con las techniques coincidentes en CAR
```{r }
mitrenet_car_from <- mitre.data$mitrenet$edges[car_mitre_from,]
mitrenet_car_to <- mitre.data$mitrenet$edges[car_mitre_to,]
```

Con las tablas, vemos que hay tacticas, techniques, grupos, mitigation y software de att&ck, CAPEC y techniques de defensa de shield. 
```{r }
table(mitrenet_car_from$to)
table(mitrenet_car_to$from)
```

## 1.3 ATT&CK

### 1.3.1 Tacticas
Cogemos las tacticas relacionadas anteriormente con los estandares y vemos su nombre y descripción.
```{r }
raw_attck$tactics[which(raw_attck$tactics$mitreid %in% unique(mitrenet_car_from$to)),]$name
#raw_attck$tactics[which(raw_attck$tactics$mitreid %in% unique(mitrenet_car_from$to)),]$description
```

### 1.3.2 Tecnicas
Cogemos las tecnicas relacionadas anteriormente con CAR y vemos su nombre y descripción.
```{r }
raw_attck$techniques[which(raw_attck$techniques$mitreid %in% inc_tech_car),]$name
#raw_attck$techniques[which(raw_attck$techniques$mitreid %in% inc_tech_car),]$description
```

Ahora probamos las tecnicas relacionadas con los estandares y vemos su nombre y descripción.
```{r }
raw_attck$techniques$mitreid[which(raw_attck$techniques$mitreid %in% unique(mitrenet_car_to$from))]
raw_attck$techniques[which(raw_attck$techniques$mitreid %in% unique(mitrenet_car_to$from)),]$name
#raw_attck$techniques[which(raw_attck$techniques$mitreid %in% unique(mitrenet_car_to$from)),]$description
```

### 1.3.3 Grupos
Miramos los grupos aparecidos y trazamos sus nombres y descripciones.
```{r }
unique(raw_attck$groups$mitreid[which(raw_attck$groups$mitreid %in% unique(mitrenet_car_to$from))])
unique(raw_attck$groups[which(raw_attck$groups$mitreid %in% unique(mitrenet_car_to$from)),]$name)
#raw_attck$groups[which(raw_attck$groups$mitreid %in% unique(mitrenet_car_to$from)),]$description
```

### 1.3.4 Software
Tambien podemos ver el software aprovechado para atacar a las empresas.
```{r }
raw_attck$software$mitreid[which(raw_attck$software$mitreid %in% unique(mitrenet_car_to$from))]
raw_attck$software[which(raw_attck$software$mitreid %in% unique(mitrenet_car_to$from)),]$name
```

### 1.3.5 Mitigation
Las tecnicas de mitigación del software aprovechado para atacar.
```{r }
unique(raw_attck$mitigation$mitreid[which(raw_attck$mitigation$mitreid %in% unique(mitrenet_car_to$from))])
unique(raw_attck$mitigation[which(raw_attck$mitigation$mitreid %in% unique(mitrenet_car_to$from)),]$name)
```

## 1.4 Shield
Otro parametro interesante son las tecnicas de defensa de shield encontradas.
```{r }
sort(table(raw_shield$shieldnet$edges$from[which(raw_shield$shieldnet$edges$from %in% unique(mitrenet_car_to$from))]))
```

## 1.5 CAPEC
Por último, hemos encontrado un CAPEC relacionado (CAPEC-177) y sus relaciones que encotramos el padre de este (CAPEC-17)
```{r }
unique(raw_capec$capecnet$edges$from[which(raw_capec$capecnet$edges$from %in% unique(mitrenet_car_to$from))])
raw_capec$capecnet$edges[which(raw_capec$capecnet$edges$from %in% unique(mitrenet_car_to$from)),]$to
```

Por otro lado, hemos cogido otro camino de relacionar incidents con capec
```{r }
inc_tech_capec <- inc_id_tech[which(inc_id_tech %in% raw_capec$capecnet$edges$to)]
capec_rel <- raw_capec$capecnet$edges[which(raw_capec$capecnet$edges$to %in% inc_id_tech),]$from
capec_rel
```
Hemos encontrado un CAPEC comun y otro de nuevo (CAPEC-187)
```{r }
raw_capec$capecnet$edges[which(raw_capec$capecnet$edges$from %in% capec_rel),]
raw_capec$capecnet$edges[which(raw_capec$capecnet$edges$from %in% c("CAPEC-17","CAPEC-186")),]
```

CAPEC-177 (draft) - Create files with the same name as files protected with a higher classification
Child of CAPEC-17, CWE-706 y T1036
CAPEC-17 (draft) - Using Malicious Files
CAPEC-18" (draft) - Malicious Automated Software Update via Redirection
Child of CAPEC-186, CWE-494 y T1072
CAPEC-186 (draft) - Malicious Software Update
buscamos tambien las relaciones con los CAPEC padres
```{r }
raw_capec$capecnet$edges[which(raw_capec$capecnet$edges$from %in% c("CAPEC-17","CAPEC-186")),]
```
## 1.6 CWE
Investigamos los CWE encontrados y el de los padres
CAPEC-177 y CAPEC-17:
CWE-706 - Use of Incorrectly-Resolved Name or Reference, CWE-732 - Incorrect Permission Assignment for Critical Resource,
CWE-285 - Improper Authorization, CWE-272 - Least Privilege Violation, CWE-59 - Improper Link Resolution Before File Access ('Link Following'),
CWE-282 - Improper Ownership Management, CWE-275 - Permission Issues, CWE-264 - Permissions, Privileges, and Access Controls y CWE-270 - Privilege Context Switching Error
CAPEC-187 y CAPEC-186:
CWE-494 - Download of Code Without Integrity Check y CWE-693 - Protection Mechanism Failure. 

Buscamos las relaciones de los CWE encontrados con otros estandares y encontramos 4 CVE's.
```{r }
which(raw_cwes$cwenet$edges$from %in% c("CWE-706","CWE-494"))
rel_cwe_cve <- raw_cwes$cwenet$edges[which(raw_cwes$cwenet$edges$from %in% c("CWE-706","CWE-494")),]$to
rel_cwe_cve
```

## 1.7 CVE
### CVE-2008-3438 
```{r }
raw_cves$cve[32837,]$description
```

### CVE-2008-3324
```{r }
raw_cves$cve[32723,]$description
```

### CVE-2001-1125 
```{r }
raw_cves$cve[3912,]$description
```

### CVE-2002-0671 
```{r }
raw_cves$cve["5033",]$description
```

Seguimos con los padres de los CAPEC encontrados.
```{r }
rel_cwe_father <- raw_capec$capecnet$edges[which(raw_capec$capecnet$edges$from %in% c("CAPEC-17","CAPEC-186")),]$to
rel_cwe_father[4:12]
rel_cwe_cve_father <- raw_cwes$cwenet$edges[which(raw_cwes$cwenet$edges$from %in% rel_cwe_father[4:12]),]$to
rel_cwe_cve_father[1:66]
#raw_cves$cve[which(raw_cves$cve$cve.id %in% rel_cwe_cve_father[1:66]),]$description
```
tenemos una larga lista de CVE's que la mayoria se basa en permisos inadecuados o descuidados hacia los ficheros
Por ejemplo, esta: XTerm in Apple Mac OS X 10.4.11 and 10.5.6, when used with luit, creates tty devices with insecure world-writable permissions, which allows local users to write to the Xterm of another user.


## 1.8 CPE
```{r }
which(raw_cpes$cpenet$edges$to %in% rel_cwe_cve)
```
No hay relacion de los CVE con CPE a traves del edges pero si si miramos en el parametro de los CVE vulnerable configuration

## Organizations
```{r }
incident_unique <- unique(incidents)
org_id <- as.character(unique(incident_unique$org))
```
resum de les instàncies d'org més nombroses
```{r }
sort(table(as.character(incident_unique$org)))
a <- sort(table(as.character(incident_unique$org)))[159:167]
```
## Industry
```{r }
sort(table(as.character(incident_unique$industry)))
test <- dplyr::select(incident_unique,org,industry)
```
resum general incidents
```{r }
apply(incident_unique, 2, function(x) length(unique(x)))
incident_unique <- incident_unique %>%
  mutate_if(is.character, as.factor)
#summary(incident_unique)

#plot_correlation(incident_unique)
industry_num <- data.frame(ind = sort(table(as.character(incident_unique$industry))))
#plot(industry_num$ind.Var1, industry_num$ind.Freq, main="Relación de ocurrencias de las industrias",cex.axis=0.40)
```

# Data Model

__TODO: Actualizar y completar el modelo__

![CyberSecurity Standards](images/standards.svg)

# Análisis

## ¿Quien estaba detras de los ataques?
Los indicios obtenidos en la sección 1.3.3 nos apuntan a un total de 56 grupos pero los más importantes por ocurrencias serian el G0045 (menuPass) en primera posición y despues los grupos G0114 (Chimera), G0096 (APT41), G0074 (Dragonfly 2.0), G0065 (Leviathan), G0061 (FIN8), G0050(APT32), G0049(OilRig) y G0027(Threat Group-3390).

```{r }
sort(table(mitrenet_car_to$from[which(mitrenet_car_to$from %in% raw_attck$groups$mitreid)]))
```


Tenemos unos cuantos grupos que son chinos o bien estan financiados/alentados por el estado chino como son menuPass, Chimera, APT41 y Threat Group-3390. Habría tambien un ruso como Dragonfly 2.0, un iraniano como OilRig y un vietnamita como APT32. Leaviathan no lo podríamos encuadrar muy bien pero tiene cosas interesantes tambien como que ataca a EEUU, Europa del este y Asia del Sur y FIN8 a unos sectores especificos.

Sectores atacados por cada grupo:

menupass -> Healthcare, defense, aerospace, government sectors, managed IT service providers, manufacturing and mining companies, and a university.

Chimera -> The semiconductor industry in Taiwan.

APT41 -> Healthcare, telecom, technology, and video game industries in 14 countries.

Dragonfly 2.0 -> Government entities and multiple U.S. critical infrastructure. 

Leaviathan -> Government organizations, industries including engineering firms, shipping and transportation, manufacturing, defense, government offices, and research universities. 

FIN8 -> Retail, restaurant, and hospitality industries.

APT-32 -> Private sector industries, foreign governments, dissidents, and journalists.

OilRig -> Industries, including financial, government, energy, chemical, and telecommunications. 

Threat-group 3390 -> Organizations in the aerospace, government, defense, technology, energy, and manufacturing sectors.

## ¿Cuál fue el objetivo?

Los sectores más atacados fueron Manufactura, Finanzas, Profesional, Información y Comercio. 
```{r }
sort(table(as.character(incident_unique$industry)))
```

y las organizaciones mas atacadas son las siguientes.
```{r }
plot(x = tail(sort(table(as.character(incident_unique$org)))))
```



## ¿Cómo realizaron los ataques?

Empezaremos explicando las tacticas y tecnicas de att&ck encontradas (sección 1.3.1 y 1.3.2), comenzando por la tactica de 'Initial Access' a traves de la cual, los atacantes penetrarian en la red mediante 'spearphising'. Tambien explotaron vulnerabilidades de los servidores webs expuestos a Internet con la tecnica de las 'Valid Accounts' que obtuvieron y abusaron de las credenciales para poder bypassear mecanismos de autenticación.

Despues, seguíriamos con la 'Privilege escalation' para poder ser root o admin a través de malas configuraciones o con la tactica de 'Scheduled Task/Job' para poder ejecutar codigo malicioso con otros permisos y así poder establecer 'Persistence' manteniendo el acceso conseguido aunque se produzcan cambios de contraseñas o correción de los debilidades usadas. Tambien, se usaría la tactica 'Command and Control' para poder comunicarse des de fuera de la red (atacante) con la red penetrada (víctima) y poder subir herramientas con la tecnica de 'Ingress Tool Transfer' o abusar del 'Windows Management Instrumentation' usando protocolos de compartir archivos como SMB.

Por otro lado, con la tactica de 'Defense evasion' se quiere pasar desapercibido para los sistemas de seguridad ofuscando los datos y desinstalando posibles controles de seguridad a través de la tecnica 'Masquerading' como su nombre indica emmascarando ciertas características como legitimas.

Finalmente, con la tactica de 'Execution', ejecutaron codigo malicioso para explorar la red y robar datos.

Ahora pasaremos a observar el software malicioso clasificado por grupos:

menuPass: Usó el troyano [ChChes] para atacar a organizaciones japonesas y como no tiene persistencia, seria una herramienta de fase inicial. Tambien utilizan la 'backdoor' [UPPERCUT] para mantener el acceso.
 
APT41: Utilizaron [ZxShell] esta backdoor y herramienta de administración remota.

Dragonfly 2.0: Emplearon [Trojan.Karagany] como herramienta de malwaremodular de acceso remoto para reconocimiento de red y [MCMD] como consola remota, ambas en Windows.

Leviathan: 


 [14] "[BONDUPDATER](https://attack.mitre.org/software/S0360) is a PowerShell backdoor used by [OilRig](https://attack.mitre.org/groups/G0049). It was first observed in November 2017 during targeting of a Middle Eastern government organization, and an updated version was observed in August 2018 being used to target a government organization with spearphishing emails.(Citation: FireEye APT34 Dec 2017)(Citation: Palo Alto OilRig Sep 2018)"                                                                                                                              
 [44] "[Denis](https://attack.mitre.org/software/S0354) is a Windows backdoor and Trojan used by [APT32](https://attack.mitre.org/groups/G0050). [Denis](https://attack.mitre.org/software/S0354) shares several similarities to the [SOUNDBITE](https://attack.mitre.org/software/S0157) backdoor and has been used in conjunction with the [Goopy](https://attack.mitre.org/software/S0477) backdoor.(Citation: Cybereason Oceanlotus May 2017)"                                                                                                                                                                                                                                                                     
 [75] "[HyperBro](https://attack.mitre.org/software/S0398) is a custom in-memory backdoor used by [Threat Group-3390](https://attack.mitre.org/groups/G0027).(Citation: Unit42 Emissary Panda May 2019)(Citation: Securelist LuckyMouse June 2018)(Citation: Hacker News LuckyMouse June 2018)"                                                                                                                                                                                                                                                                    [83] "[KOMPROGO](https://attack.mitre.org/software/S0156) is a signature backdoor used by [APT32](https://attack.mitre.org/groups/G0050) that is capable of process, file, and registry management. (Citation: FireEye APT32 May 2017)"                                                                              
 [116] "[OSX_OCEANLOTUS.D](https://attack.mitre.org/software/S0352) is a MacOS backdoor that has been used by [APT32](https://attack.mitre.org/groups/G0050).(Citation: TrendMicro MacOS April 2018)"   
 
 [116] "[OSX_OCEANLOTUS.D](https://attack.mitre.org/software/S0352) is a MacOS backdoor that has been used by [APT32](https://attack.mitre.org/groups/G0050).(Citation: TrendMicro MacOS April 2018)"  


[109] "[NanHaiShu](https://attack.mitre.org/software/S0228) is a remote access tool and JScript backdoor used by [Leviathan](https://attack.mitre.org/groups/G0065). [NanHaiShu](https://attack.mitre.org/software/S0228) has been used to target government and private-sector organizations that have relations to the South China Sea dispute. (Citation: Proofpoint Leviathan Oct 2017) (Citation: fsecure NanHaiShu July 2016)" 

[121] "[Orz](https://attack.mitre.org/software/S0229) is a custom JavaScript backdoor used by [Leviathan](https://attack.mitre.org/groups/G0065). It was observed being used in 2014 as well as in August 2017 when it was dropped by Microsoft Publisher files. (Citation: Proofpoint Leviathan Oct 2017) (Citation: FireEye Periscope March 2018)"   

[128] "[PUNCHBUGGY](https://attack.mitre.org/software/S0196) is a backdoor malware used by [FIN8](https://attack.mitre.org/groups/G0061) that has been observed targeting POS networks in the hospitality industry. (Citation: Morphisec ShellTea June 2019)(Citation: FireEye Fin8 May 2016) (Citation: FireEye Know Your Enemy FIN8 Aug 2016)" 

[120] "[OopsIE](https://attack.mitre.org/software/S0264) is a Trojan used by [OilRig](https://attack.mitre.org/groups/G0049) to remotely execute commands as well as upload/download files to/from victims. (Citation: Unit 42 OopsIE! Feb 2018)"

[142] "[RDAT](https://attack.mitre.org/software/S0495) is a backdoor used by the suspected Iranian threat group [OilRig](https://attack.mitre.org/groups/G0049). [RDAT](https://attack.mitre.org/software/S0495) was originally identified in 2017 and targeted companies in the telecommunications sector.(Citation: Unit42 RDAT July 2020)"   
 
 

#relacionar grupos con software usado en attack

## ¿Cómo podemos protegernos?

## ¿Qué podemos hacer para prevenir futuros ataques?

## ¿Sería posible predecir ataques?



