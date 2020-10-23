#ifndef QUEUE_H
#define QUEUE_H

struct queue;
typedef struct queue *queue;

// creaza o coada goala
extern queue queue_create(void);

// insereaza un element la sfarsitul cozii
extern void queue_enq(queue q, void *element);

// sterge elementul de la inceputul cozii si il returneaza
extern void *queue_deq(queue q);

// returneaza daca coada e goala sau nu
extern int queue_empty(queue q);

#endif
