%module nfqueue

%{
#include <nfq.h>

#include <nfq_common.h>

#include <exception.h>

#include "config.h"
%}

%include exception.i




#if defined(SWIGPYTHON)

%include python/libnetfilter_queue_python.i

#endif


%extend queue {

%exception {
        char *err;
        clear_exception();
        $action
        if ((err = check_exception())) {
                SWIG_exception(SWIG_RuntimeError, err);
        }
}

        int open();
        void close();
        int bind(int);
        int unbind(int);
        int create_queue(int);
        int fast_open(int, int);
        int set_queue_maxlen(int);
        int try_run();
        int get_fd();
        int set_mode(int);
        int process_pending(int=0);
};

%extend payload {
        int get_nfmark();
        int get_indev();
        int get_outdev();
        int get_physindev();
        int get_physoutdev();

unsigned int get_length(void) {
        return self->len;
}

int set_verdict(int d) {
        return nfq_set_verdict(self->qh, self->id, d, 0, NULL);
}

int set_verdict_mark(int d, int mark) {
%#ifdef HAVE_NFQ_SET_VERDICT2
        return nfq_set_verdict2(self->qh, self->id, d, htonl(mark), 0, NULL);
%#else
        return nfq_set_verdict_mark(self->qh, self->id, d, htonl(mark), 0, NULL);
%#endif
}

int set_verdict_modified(int d, char *new_payload, int new_len) {
        return nfq_set_verdict(self->qh, self->id, d, new_len, new_payload);
}

int set_verdict_mark_modified(int d, int mark, char *new_payload, int new_len) {
%#ifdef HAVE_NFQ_SET_VERDICT2
        return nfq_set_verdict2(self->qh, self->id, d, htonl(mark), new_len, new_payload);
%#else
        return nfq_set_verdict_mark(self->qh, self->id, d, htonl(mark), new_len, new_payload);
%#endif
}

};

%include "nfq.h"
%include "nfq_constants.h"

const char * nfq_bindings_version(void);

