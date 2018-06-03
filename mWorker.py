#!/use/bin/python

import multiprocessing

'''
Class representative a worker that executes the tasks in the "task queue"
and puts the result in the "result queue"
'''
class Worker(multiprocessing.Process):
    
    def __init__(self, task_queue, result_queue):
        multiprocessing.Process.__init__(self)
        self.task_queue = task_queue
        self.result_queue = result_queue

    def run(self):
        while True:
            next_task = self.task_queue.get()
            # it means shutdown
            if next_task is None:
                self.task_queue.task_done()
                break
            #print '%s starts working on:  %s' % (proc_name, next_task)
            answer = next_task()
            self.task_queue.task_done()
            self.result_queue.put(answer)
        return