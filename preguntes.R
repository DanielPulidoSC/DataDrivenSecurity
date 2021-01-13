#Primer ordenem les variables d'indústria per les ocurrències
sort(table(incidents.data["industry"]))
#També ordenem les organitzacions
sort(table(incidents.data["org"]))
#Obtenim la columna mitre_attack
attacks <- dplyr::select(.data = incidents.data, mitre_attack)
#o d'aquesta altra manera
mitre.attack <- incidents.data$mitre_attack
#Finalment, fotem la llista de dataframes en un sol dataframe
mitre.final = data.table::rbindlist(mitre.attack)
#o d'aquesta altra manera
mitre.final <- dplyr::bind_rows(mitre.attack)
#per altra banda si ho volem fer directe, fariem el seguent
raw_incidents <- readRDS(file = "data/incidents.rds")
incidents <- raw_incidents %>% unnest(mitre_attack)


## Empieza la exploración
# id's unicos y en formato caracter
inc_id_tech <- as.character(unique(incidents$id))
# id's ordenadors por ocurrencia
sort(table(as.character(incidents$id)))
# comparamos las techniques de los incidents con las techniques de car 
which(inc_id_tech %in% raw_car$carnet$edges$to)
# mostramos las techniques coincidentes con su id
inc_tech_car <- inc_id_tech[which(inc_id_tech %in% raw_car$carnet$edges$to)]
# techniques con mitrenet
k <- inc_id_tech[which(inc_id_tech %in% mitre.data$mitrenet$edges$from)]
# tecnhiques de car con mitrenet
from <- inc_id_tech[which(inc_tech_car %in% mitre.data$mitrenet$edges$from)]
# relation mitrenet from con car
car_mitre_from <- which(mitre.data$mitrenet$edges$from %in% inc_tech_car)
# relation mitrenet to con car
car_mitre_to <- which(mitre.data$mitrenet$edges$to %in% inc_tech_car)
#pruebas 
mitre.data$mitrenet$edges$from[10588]
#pruebas
mitre.data$mitrenet$edges$to[10588]
#pruebas
mitre.data$mitrenet$edges[10588,]
# mitrenet from con car y to con car
mitrenet_car_from <- mitre.data$mitrenet$edges[car_mitre_from,]
mitrenet_car_to <- mitre.data$mitrenet$edges[car_mitre_to,]
# pruebas
table(mitrenet_car_from)
table(mitrenet_car_to)
# tactics de attack
sort(table(mitrenet_car_from$to))
# groups de attack
sort(table(mitrenet_car_to$from))
DataExplorer::plot_correlation(data.frame(to = mitrenet_car_to$to, from = mitrenet_car_to$from))
