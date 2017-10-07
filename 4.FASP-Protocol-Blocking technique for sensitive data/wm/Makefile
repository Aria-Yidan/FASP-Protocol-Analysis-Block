objects =  wm.o

nlusr : $(objects)
	gcc -o wm $(objects)

nlusr.o : wm.c
	gcc -c wm.c

clean:
	rm wm $(objects)