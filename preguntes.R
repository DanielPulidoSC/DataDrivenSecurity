---
title: "Incident analysis based on MITRE standards"
author: "Humbert Costas"
date: "11/01/2021"
output: html_document
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
mitre.data <- mitre::getMitreNetwork(verbose = F)
```

## Incidentes

Load incidents data set and unnest ATT&CK column.

```{r ds_incidents}
mitre.data <- mitre::getLatestDataSet()
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

```{r ds_car}
raw_capec <- mitre.data$standards$capec
```


## Empieza la exploración en incidents
## id's unicos y en formato caracter
inc_id_tech <- as.character(unique(incidents$id))

## id's ordenadors por ocurrencia
sort(table(as.character(incidents$id)))

##CAR##
## comparamos las techniques de los incidents con las techniques relacionadas de car 
which(inc_id_tech %in% raw_car$carnet$edges$to)

## mostramos las techniques coincidentes con su id encontradas en la rel de car
inc_tech_car <- inc_id_tech[which(inc_id_tech %in% raw_car$carnet$edges$to)]

## techniques con mitrenet relacionadas con techniques incidents
k <- inc_id_tech[which(inc_id_tech %in% mitre.data$mitrenet$edges$from)]

## tecnhiques de mitrenet relacionadas con las techniques relacionadas en car en incidents
from <- inc_id_tech[which(inc_tech_car %in% mitre.data$mitrenet$edges$from)]

## relation mitrenet techniques from con techniques in car
car_mitre_from <- which(mitre.data$mitrenet$edges$from %in% inc_tech_car)

## relation mitrenet to con car
car_mitre_to <- which(mitre.data$mitrenet$edges$to %in% inc_tech_car)

## pruebas 
mitre.data$mitrenet$edges$from[10588]
mitre.data$mitrenet$edges$to[10588]
mitre.data$mitrenet$edges[10588,]

## mitrenet from con car y to con car
mitrenet_car_from <- mitre.data$mitrenet$edges[car_mitre_from,]
mitrenet_car_to <- mitre.data$mitrenet$edges[car_mitre_to,]

## pruebas
table(mitrenet_car_from)
table(mitrenet_car_to)
table(mitrenet_car_from$to)

## tactics y techniques de attack
sort(table(mitrenet_car_from$to))
raw_attck$tactics[which(raw_attck$tactics$mitreid %in% unique(mitrenet_car_from$to)),]
#nombres tacticas
raw_attck$tactics[which(raw_attck$tactics$mitreid %in% unique(mitrenet_car_from$to)),]$name
#nombres techniques
raw_attck$techniques[which(raw_attck$techniques$mitreid %in% inc_tech_car),]$name
raw_attck$techniques[which(raw_attck$techniques$mitreid %in% inc_tech_car),]$description
raw_attck$techniques$mitreid[which(raw_attck$techniques$mitreid %in% unique(mitrenet_car_to$from))]
raw_attck$techniques[which(raw_attck$techniques$mitreid %in% unique(mitrenet_car_to$from)),]$name

#Pregunta 3 (explicar las tecnicas usadas)

## groups de attack
sort(table(mitrenet_car_to$from))
raw_attck$groups$mitreid[which(raw_attck$groups$mitreid %in% unique(mitrenet_car_to$from))]
raw_attck$groups[which(raw_attck$groups$mitreid %in% unique(mitrenet_car_to$from)),]$name
#Pregunta 1 (nombrar grupos que salen más y que tipo de ataques llevaban a cabo)

## software usado
sort(table(mitrenet_car_to$from))
raw_attck$software$mitreid[which(raw_attck$software$mitreid %in% unique(mitrenet_car_to$from))]
raw_attck$software[which(raw_attck$software$mitreid %in% unique(mitrenet_car_to$from)),]$name

## mitigation
sort(table(mitrenet_car_to$from))
raw_attck$mitigation$mitreid[which(raw_attck$mitigation$mitreid %in% unique(mitrenet_car_to$from))]
raw_attck$mitigation[which(raw_attck$mitigation$mitreid %in% unique(mitrenet_car_to$from)),]$name

## DTE - tecnicas defensa shield
sort(table(mitrenet_car_to$from))
raw_shield$shieldnet$edges$from[which(raw_shield$shieldnet$edges$from %in% unique(mitrenet_car_to$from))]
sort(table(raw_shield$shieldnet$edges$from[which(raw_shield$shieldnet$edges$from %in% unique(mitrenet_car_to$from))]))

#DataExplorer::plot_correlation(data.frame(to = mitrenet_car_to$to, from = mitrenet_car_to$from))

##CAPEC##

## relacio de tech incidents amb capec
inc_tech_capec <- inc_id_tech[which(inc_id_tech %in% raw_capec$capecnet$edges$to)]
## capec id
capec_rel <- raw_capec$capecnet$edges[which(raw_capec$capecnet$edges$to %in% inc_id_tech),]$from
# CAPEC-177 y CAPEC-187
# los buscamos via grafica o via terminal
raw_capec$capecnet$edges[which(raw_capec$capecnet$edges$from %in% capec_rel),]$to
# "CAPEC-177" (draft) - Create files with the same name as files protected with a higher classification
# Child of CAPEC-17, CWE-706 y T1036
# "CAPEC-187" (draft) - Malicious Automated Software Update via Redirection
# Child of CAPEC-186, CWE-494 y T1072




## relation mitrenet techniques from with capec
capec_mitre_from <- which(mitre.data$mitrenet$edges$from %in% inc_tech_capec)

## relation mitrenet techniques to with capec
capec_mitre_to <- which(mitre.data$mitrenet$edges$to %in% inc_tech_capec)

## mitrenet from con capec y to con capecs
mitrenet_capec_to <- mitre.data$mitrenet$edges[capec_mitre_to,]
mitrenet_capec_from <- mitre.data$mitrenet$edges[capec_mitre_from,]

## pillamos la mitrenet_capec_from y buscamos las tactics en attck

## pillamos el mitrenet_capec_to y buscamos grupos, mitigations, software, techniques de attck y dte y capec




## organizations
incident_unique <- unique(incidents)
org_id <- as.character(unique(incident_unique$org))

## resum de les instàncies d'org més nombroses
sort(table(as.character(incident_unique$org)))
length(sort(table(as.character(incident_unique$org))))

## industry
sort(table(as.character(incident_unique$industry)))

## resum general incidents
apply(incident_unique, 2, function(x) length(unique(x)))
incident_unique <- incident_unique %>%
  mutate_if(is.character, as.factor)
summary(incident_unique)

plot_correlation(incident_unique)
industry_num <- data.frame(ind = sort(table(as.character(incident_unique$industry))))
plot(industry_num$ind.Var1, industry_num$ind.Freq, main="Relación de ocurrencias de las industrias",cex.axis=0.40)


# Data Model

__TODO: Actualizar y completar el modelo__

![CyberSecurity Standards](images/standards.svg)

# Análisis

## ¿Quien estaba detras de los ataques?

## ¿Cuál fue el objetivo?

## ¿Cómo realizaron los ataques?

## ¿Cómo podemos protegernos?

## ¿Qué podemos hacer para prevenir futuros ataques?

## ¿Sería posible predecir ataques?



