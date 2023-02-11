#ifndef __EXPR_H
#define __EXPR_H

struct symbol_table {
    int token;
    int class;
    char *name;
    long hash;
    int ref;
    int type;
    int nr_elm; //array
    long value;
};

struct expr_prog {
    struct symbol_table *symtab;
    int nr_syms;
    char *data; //global var
    int datasize;
    char *str;
    long *insn;
    int nr_insn;
    int debug;
};

struct global_var_declare {
    const char *name;
    int offset;
    int size;
    int elementsize;
};

struct expr_prog *expr_compile(char *expr_str, struct global_var_declare *declare);
long expr_run(struct expr_prog *prog);
int expr_load_glo(struct expr_prog *prog, const char *name, long value);
int expr_load_data(struct expr_prog *prog, void *d, int size);
void expr_destroy(struct expr_prog *prog);
void expr_dump(struct expr_prog *prog);


#endif

