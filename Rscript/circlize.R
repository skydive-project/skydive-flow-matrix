#!/usr/bin/R

# install.packages("circlize")
library(circlize)

# data from : skydive-flow-matrix --analyzer 10.0.0.15:8082 --username admin --password password
fm <- read.csv(file="flow-matrix.csv", header=TRUE, sep=",")

name=fm$binA #paste(fm$hostA, fm$binA, sep=":")
feature=fm$binB 

dat <- data.frame(name,feature)
dat <- with(dat, table(name, feature))

#png(filename="out.png", width = 768, height = 768)
chordDiagram(as.data.frame(dat), transparency = 0.6)
#dev.off()
