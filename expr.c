/*
 * Expression compiler and simulator.
 * https://github.com/rswier/c4.git
 *
 * Instruction Set
 *   pc: instruction register
 *   sp: stack pointer
 *   bp: frame pointer
 *   a : general purpose register
 *
 * Opcode      Instruction        #Description
 * LEA imm64   LEA a, imm64[bp]   #case LEA: a = (long)(bp + *pc++); break;                              // load local address
 * IMM imm64   IMM a, imm64       #case IMM: a = *pc++; break;                                           // load global address or immediate
 * JMP imm64   JMP imm64          #case JMP: pc = (long *)*pc; break;                                    // jump
 * JSR imm64   JSR imm64          #case JSR: { *--sp = (long)(pc + 1); pc = (long *)*pc; } break;        // jump to subroutine
 * BZ  imm64   BZ  imm64          #case BZ:  pc = a ? pc + 1 : (long *)*pc; break;                       // branch if zero
 * BNZ imm64   BNZ imm64          #case BNZ: pc = a ? (long *)*pc : pc + 1; break;                       // branch if not zero
 * ENT imm64   ENT imm64          #case ENT: { *--sp = (long)bp; bp = sp; sp = sp - *pc++; } break;      // enter subroutine
 * ADJ imm64   ADJ imm64          #case ADJ: sp = sp + *pc++; break;                                     // stack adjust
 * LI  imm64   LI  imm64          #case LI:  switch(*pc++) { case sizeof(char): a = *(char *)a; ...}     // load int
 * SI  imm64   SI  imm64          #case SI:  switch(*pc++) { case sizeof(char): *(char *)*sp++ = a; ...} // store int
 * LEV         LEV                #case LEV: { sp = bp; bp = (long *)*sp++; pc = (long *)*sp++; } break; // leave subroutine
 * PSH         PSH a              #case PSH: *--sp = a; break;                                           // push
 *                                #
 * OR          OR  a, [sp]        #case OR:  a = *sp++ |  a; break;
 * XOR         XOR a, [sp]        #case XOR: a = *sp++ ^  a; break;
 * AND         AND a, [sp]        #case AND: a = *sp++ &  a; break;
 * EQ          EQ  a, [sp]        #case EQ:  a = *sp++ == a; break;
 * NE          NE  a, [sp]        #case NE:  a = *sp++ != a; break;
 * LT          LT  a, [sp]        #case LT:  a = *sp++ <  a; break;
 * GT          GT  a, [sp]        #case GT:  a = *sp++ >  a; break;
 * LE          LE  a, [sp]        #case LE:  a = *sp++ <= a; break;
 * GE          GE  a, [sp]        #case GE:  a = *sp++ >= a; break;
 * SHL         SHL a, [sp]        #case SHL: a = *sp++ << a; break;
 * SHR         SHR a, [sp]        #case SHR: a = *sp++ >> a; break;
 * ADD         ADD a, [sp]        #case ADD: a = *sp++ +  a; break;
 * SUB         SUB a, [sp]        #case SUB: a = *sp++ -  a; break;
 * MUL         MUL a, [sp]        #case MUL: a = *sp++ *  a; break;
 * DIV         DIV a, [sp]        #case DIV: a = *sp++ /  a; break;
 * MOD         MOD a, [sp]        #case MOD: a = *sp++ %  a; break;
 *                                #
 * PRTF        PRTF a, [sp]       #case PRTF: t = sp + pc[1]; a = printf((char *)t[-1], t[-2], ...); break;
 * KSYM        KSYM a, [sp]       #case KSYM: a = ksymbol(*sp); break;
 *                                #case EXIT: return a;
**/

#include <stdio.h>
#include <stdlib.h>
#include <memory.h>
#include <unistd.h>
#include <setjmp.h>
#include <arpa/inet.h>

#include <monitor.h>
#include <tep.h>
#include <expr.h>
#include <stack_helpers.h>


char *p, *lp, // current position in source code
     *data, *str;   // data/string pointer

long *e, *le,  // current position in emitted code
    tk,       // current token
    ival,     // current token value
    ty,       // current expression type
    loc;      // local variable offset

struct symbol_table *id;       // currently parsed identifier
struct symbol_table *symtab;     // symbol table (simple list of identifiers)
int n_syms, nr_syms;

jmp_buf synerr_jmp;


// tokens and classes (operators last and in precedence order)
enum {
    Num = 128, Fun, Sys, Glo, Loc, Id,
    Int, Sizeof,
    Assign, Cond, Lor, Lan, Or, Xor, And, Eq, Ne, Lt, Gt, Le, Ge, Shl, Shr, Add, Sub, Mul, Div, Mod, Inc, Dec, Brak
};

// opcodes
enum { LEA ,IMM ,JMP ,JSR ,BZ  ,BNZ ,ENT ,ADJ ,LI  ,SI  ,LEV ,PSH ,
       OR  ,XOR ,AND ,EQ  ,NE  ,LT  ,GT  ,LE  ,GE  ,SHL ,SHR ,ADD ,SUB ,MUL ,DIV ,MOD ,
       PRTF, KSYM, NTHL, NTHS, EXIT };

// types
enum { CHAR, SHORT, INT, LONG, ARRAY, PTR = 0x8 };

#define INSN "LEA ,IMM ,JMP ,JSR ,BZ  ,BNZ ,ENT ,ADJ ,LI  ,SI  ,LEV ,PSH ," \
             "OR  ,XOR ,AND ,EQ  ,NE  ,LT  ,GT  ,LE  ,GE  ,SHL ,SHR ,ADD ,SUB ,MUL ,DIV ,MOD ," \
             "PRTF,KSYM,NTHL,NTHS,EXIT,"

#define ADD_KEY(name, _token, _type) \
    { p = (char *)name; { next(); id->token = _token; id->class = 0; id->type = _type; id->value = 0; } }
#define ADD_LIB(name, _type, insn) \
    { p = (char *)name; { next(); id->class = Sys; id->type = _type; id->value = insn; } }

#define TK_SHIFT 6
#define HASH(tk, len) (((tk) << TK_SHIFT) + (len))
#define LEN(hash) ((hash) & ((1 << TK_SHIFT) - 1))

static void synerr(const char *s)
{
    printf("%s\n", lp);
    printf("%*s%s\n", (int)(p-lp+1), "^ ", s);
    longjmp(synerr_jmp, -1);
}

static void next(void)
{
    char *pp;

    while ((tk = *p)) {
        ++p;
        if (tk == '\n') ;
        else if (tk == '#') {
            while (*p != 0 && *p != '\n') ++p;
        }
        else if ((tk >= 'a' && tk <= 'z') || (tk >= 'A' && tk <= 'Z') || tk == '_') {
            pp = p - 1;
            while ((*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') || (*p >= '0' && *p <= '9') || *p == '_')
                tk = tk * 147 + *p++;
            tk = HASH(tk, p - pp);
            id = symtab;
            while (id->token && id < symtab+nr_syms) {
                if (tk == id->hash && !memcmp(id->name, pp, p - pp)) { tk = id->token; return; }
                id ++;
            }
            if (id == symtab+nr_syms) {
                nr_syms += 16;
                symtab = realloc(symtab, nr_syms*sizeof(*symtab));
                id = &symtab[n_syms];
            }
            n_syms ++;
            id->name = pp;
            id->hash = tk;
            tk = id->token = Id;
            return;
        }
        else if (tk >= '0' && tk <= '9') {
            if ((ival = tk - '0')) {
                while (*p >= '0' && *p <= '9') ival = ival * 10 + *p++ - '0';
            }
            else if (*p == 'x' || *p == 'X') {
                while ((tk = *++p) && ((tk >= '0' && tk <= '9') || (tk >= 'a' && tk <= 'f') || (tk >= 'A' && tk <= 'F')))
                    ival = ival * 16 + (tk & 15) + (tk >= 'A' ? 9 : 0);
            } else {
                while (*p >= '0' && *p <= '7')
                    ival = ival * 8 + *p++ - '0';
            }
            tk = Num;
            return;
        }
        else if (tk == '/') {
            if (*p == '/') {
                ++p;
                while (*p != 0 && *p != '\n') ++p;
            } else {
                tk = Div;
                return;
            }
        }
        else if (tk == '\'' || tk == '"') {
            pp = str;
            while (*p != 0 && *p != tk) {
                if ((ival = *p++) == '\\') {
                    if ((ival = *p++) == 'n') ival = '\n';
                }
                if (tk == '"') *str++ = ival;
            }
            ++p; *str++ = '\0';
            if (tk == '"') ival = (long)pp;
            else tk = Num;
            return;
        }
        else if (tk == '=') { if (*p == '=') { ++p; tk = Eq; } else tk = Assign; return; }
        else if (tk == '+') { if (*p == '+') { ++p; tk = Inc; } else tk = Add; return; }
        else if (tk == '-') { if (*p == '-') { ++p; tk = Dec; } else tk = Sub; return; }
        else if (tk == '!') { if (*p == '=') { ++p; tk = Ne; } return; }
        else if (tk == '<') { if (*p == '=') { ++p; tk = Le; } else if (*p == '<') { ++p; tk = Shl; } else tk = Lt; return; }
        else if (tk == '>') { if (*p == '=') { ++p; tk = Ge; } else if (*p == '>') { ++p; tk = Shr; } else tk = Gt; return; }
        else if (tk == '|') { if (*p == '|') { ++p; tk = Lor; } else tk = Or; return; }
        else if (tk == '&') { if (*p == '&') { ++p; tk = Lan; } else tk = And; return; }
        else if (tk == '^') { tk = Xor; return; }
        else if (tk == '%') { tk = Mod; return; }
        else if (tk == '*') { tk = Mul; return; }
        else if (tk == '[') { tk = Brak; return; }
        else if (tk == '?') { tk = Cond; return; }
        else if (tk == '~' || tk == ';' || tk == '{' || tk == '}' || tk == '(' || tk == ')' || tk == ']' || tk == ',' || tk == ':') return;
    }
}

static void expr(int lev)
{
    long t, *d;

    if (!tk) { synerr("unexpected eof in expression"); }
    else if (tk == Num) { *++e = IMM; *++e = ival; next(); ty = INT; }
    else if (tk == '"') {
        *++e = IMM; *++e = ival; next();
        while (tk == '"') next();
        ty = PTR;
    }
    else if (tk == Sizeof) {
        next(); if (tk == '(') next(); else { synerr("open paren expected in sizeof"); }
        if (tk == Int) { ty = id->type; next(); } else { synerr("wrong type"); }
        while (tk == Mul) { next(); ty = ty + PTR; }
        if (tk == ')') next(); else { synerr("close paren expected in sizeof"); }
        *++e = IMM; *++e = (ty >= PTR) ? sizeof(void *) : (1 << ty);
        ty = INT;
    }
    else if (tk == Id) {
        struct symbol_table *s = id;
        next();
        if (tk == '(') {
            next();
            t = 0;
            while (tk != ')') { expr(Assign); *++e = PSH; ++t; if (tk == ',') next(); }
            next();
            if (s->class == Sys) { *++e = s->value; s->ref++; }
            else if (s->class == Fun) { *++e = JSR; *++e = s->value; s->ref++; }
            else { synerr("bad function call"); }
            if (t) { *++e = ADJ; *++e = t; }
            ty = s->type;
        }
        else if (s->class == Num) { *++e = IMM; *++e = s->value; ty = INT; }
        else {
            if (s->class == Loc) { *++e = LEA; *++e = loc - s->value; s->ref++; }
            else if (s->class == Glo) { *++e = IMM; *++e = s->value; s->ref++; }
            else { synerr("undefined variable"); }
            ty = s->type;
            if (ty & ARRAY) { ty &= ~ARRAY; ty |= PTR; }
            else { *++e = LI; *++e = (ty >= PTR) ? sizeof(void *) : (1 << ty); }
        }
    }
    else if (tk == '(') {
        next();
        if (tk == Int) {
            t = id->type; next();
            while (tk == Mul) { next(); t = t + PTR; }
            if (tk == ')') next(); else { synerr("bad cast"); }
            expr(Inc);
            ty = t;
        }
        else {
            expr(Assign);
            if (tk == ')') next(); else { synerr("close paren expected"); }
        }
    }
    else if (tk == Mul) {
        next(); expr(Inc);
        if (ty >= PTR) ty = ty - PTR; else { synerr("bad dereference"); }
        *++e = LI; *++e = (ty >= PTR) ? sizeof(void *) : (1 << ty);
    }
    else if (tk == And) {
        next(); expr(Inc);
        if (*(e-1) == LI) e -= 2; else { synerr("bad address-of"); }
        ty = ty + PTR;
    }
    else if (tk == '!') { next(); expr(Inc); *++e = PSH; *++e = IMM; *++e = 0; *++e = EQ; ty = INT; }
    else if (tk == '~') { next(); expr(Inc); *++e = PSH; *++e = IMM; *++e = -1; *++e = XOR; ty = INT; }
    else if (tk == Add) { next(); expr(Inc); ty = INT; }
    else if (tk == Sub) {
        next(); *++e = IMM;
        if (tk == Num) { *++e = -ival; next(); } else { *++e = -1; *++e = PSH; expr(Inc); *++e = MUL; }
        ty = INT;
    }
    else if (tk == Inc || tk == Dec) {
        t = tk; next(); expr(Inc);
        if (*(e-1) == LI) { *(e-1) = PSH; ++e; *e = *(e-1); *(e-1) = LI; }
        else { synerr("bad lvalue in pre-increment"); }
        *++e = PSH;
        *++e = IMM; *++e = (ty>=PTR+PTR) ? sizeof(void *) : (ty>=PTR?(1<<(ty-PTR)):1);
        *++e = (t == Inc) ? ADD : SUB;
        *++e = SI; *++e = (ty >= PTR) ? sizeof(void *) : (1 << ty);
    }
    else { synerr("bad expression"); }

    while (tk >= lev) { // "precedence climbing" or "Top Down Operator Precedence" method
        t = ty;
        if (tk == Assign) {
            next();
            if (*(e-1) == LI) *--e = PSH; else { synerr("bad lvalue in assignment"); }
            expr(Assign); ty = t; *++e = SI; *++e = (ty >= PTR) ? sizeof(void *) : (1 << ty);
        }
        else if (tk == Cond) {
            next();
            *++e = BZ; d = ++e;
            expr(Assign);
            if (tk == ':') next(); else { synerr("conditional missing colon"); }
            *d = (long)(e + 3); *++e = JMP; d = ++e;
            expr(Cond);
            *d = (long)(e + 1);
        }
        else if (tk == Lor) { next(); *++e = BNZ; d = ++e; expr(Lan); *d = (long)(e + 1); ty = INT; }
        else if (tk == Lan) { next(); *++e = BZ;  d = ++e; expr(Or);  *d = (long)(e + 1); ty = INT; }
        else if (tk == Or)  { next(); *++e = PSH; expr(Xor); *++e = OR;  ty = INT; }
        else if (tk == Xor) { next(); *++e = PSH; expr(And); *++e = XOR; ty = INT; }
        else if (tk == And) { next(); *++e = PSH; expr(Eq);  *++e = AND; ty = INT; }
        else if (tk == Eq)  { next(); *++e = PSH; expr(Lt);  *++e = EQ;  ty = INT; }
        else if (tk == Ne)  { next(); *++e = PSH; expr(Lt);  *++e = NE;  ty = INT; }
        else if (tk == Lt)  { next(); *++e = PSH; expr(Shl); *++e = LT;  ty = INT; }
        else if (tk == Gt)  { next(); *++e = PSH; expr(Shl); *++e = GT;  ty = INT; }
        else if (tk == Le)  { next(); *++e = PSH; expr(Shl); *++e = LE;  ty = INT; }
        else if (tk == Ge)  { next(); *++e = PSH; expr(Shl); *++e = GE;  ty = INT; }
        else if (tk == Shl) { next(); *++e = PSH; expr(Add); *++e = SHL; ty = INT; }
        else if (tk == Shr) { next(); *++e = PSH; expr(Add); *++e = SHR; ty = INT; }
        else if (tk == Add) {
            next(); *++e = PSH; expr(Mul);
            if ((ty = t) > PTR) { *++e = PSH; *++e = IMM; *++e = (ty>=PTR+PTR)?sizeof(void *):(1<<(ty-PTR)); *++e = MUL;  }
            *++e = ADD;
        }
        else if (tk == Sub) {
            next(); *++e = PSH; expr(Mul);
            if (t > PTR && t == ty) { *++e = SUB; *++e = PSH; *++e = IMM; *++e = (ty>=PTR+PTR)?sizeof(void *):(1<<(ty-PTR)); *++e = DIV; ty = INT; }
            else if ((ty = t) > PTR) { *++e = PSH; *++e = IMM; *++e = (ty>=PTR+PTR)?sizeof(void *):(1<<(ty-PTR)); *++e = MUL; *++e = SUB; }
            else *++e = SUB;
        }
        else if (tk == Mul) { next(); *++e = PSH; expr(Inc); *++e = MUL; ty = INT; }
        else if (tk == Div) { next(); *++e = PSH; expr(Inc); *++e = DIV; ty = INT; }
        else if (tk == Mod) { next(); *++e = PSH; expr(Inc); *++e = MOD; ty = INT; }
        else if (tk == Inc || tk == Dec) {
            if (*(e-1) == LI) { *(e-1) = PSH; ++e; *e = *(e-1); *(e-1) = LI; }
            else { synerr("bad lvalue in post-increment"); }
            *++e = PSH;
            *++e = IMM; *++e = (ty>=PTR+PTR) ? sizeof(void *) : (ty>=PTR?(1<<(ty-PTR)):1);//*++e = (ty > PTR) ? sizeof(long) : sizeof(char);
            *++e = (tk == Inc) ? ADD : SUB;
            *++e = SI; *++e = (ty >= PTR) ? sizeof(void *) : (1 << ty);
            *++e = PSH;
            *++e = IMM; *++e = (ty>=PTR+PTR) ? sizeof(void *) : (ty>=PTR?(1<<(ty-PTR)):1);//(ty > PTR) ? sizeof(long) : sizeof(char);
            *++e = (tk == Inc) ? SUB : ADD;
            next();
        }
        else if (tk == Brak) {
            next(); *++e = PSH; expr(Assign);
            if (tk == ']') next(); else { synerr("close bracket expected"); }
            if (t > PTR) { *++e = PSH; *++e = IMM; *++e = (t>=PTR+PTR)?sizeof(void *):(1<<(t-PTR)); *++e = MUL;  }
            else if (t < PTR) { synerr("pointer type expected"); }
            *++e = ADD;
            ty = t - PTR;
            *++e = LI; *++e = (ty >= PTR) ? sizeof(void *) : (1 << ty);
        }
        else { synerr("compiler error"); }
    }
}

static const char *ksymbol(unsigned long func)
{
    char *name = function_resolver(NULL, (unsigned long long *)&func, NULL);
    return name ? : "Unknown";
}

struct expr_prog *expr_compile(char *expr_str, struct global_var_declare *declare)
{
    int i, err;
    int nr_insn = 1024;
    int datasize = 256;
    int strsize = strlen(expr_str);
    char *d, *s;
    struct expr_prog *prog = NULL;

    // reset
    loc = 0;
    n_syms = 0;
    nr_syms = 16;
    symtab = calloc(nr_syms, sizeof(struct symbol_table));
    data = d = malloc(datasize);
    str = s = malloc(strsize);
    le = e = calloc(nr_insn, sizeof(long));

    if (!symtab || !data || !str || !le)
        goto err_return;

    // add keywords to symbol table
    ADD_KEY("char", Int, CHAR);
    ADD_KEY("short", Int, SHORT);
    ADD_KEY("int", Int, INT);
    ADD_KEY("long", Int, LONG);
    ADD_KEY("sizeof", Sizeof, INT);

    // add library to symbol table
    // int printf(const char *format, ...);
    ADD_LIB("printf", INT, PRTF);
    // char *ksymbol(unsigned long func);
    ADD_LIB("ksymbol", CHAR | PTR, KSYM);
    // uint32_t ntohl(uint32_t netlong);
    ADD_LIB("ntohl", INT, NTHL);
    // uint16_t ntohs(uint16_t netshort);
    ADD_LIB("ntohs", SHORT, NTHS);

    data = d; // reset data
    memset(d, 0, datasize);
    str = s; // reset str
    memset(s, 0, strsize);

    // global variable declaration
    if (declare) {
        struct global_var_declare *save = declare;
        int max_offset;
    restart:
        max_offset = 0;
        while (declare->name) {
            p = (char *)declare->name;
            next();
            id->class = Glo;
            switch (declare->elementsize) {
                case sizeof(char) : id->type = CHAR; break;
                case sizeof(short) : id->type = SHORT; break;
                case sizeof(int) : id->type = INT; break;
                case sizeof(long) : id->type = LONG; break;
                default: goto err_return;
            }
            if (declare->size != declare->elementsize)
                id->type |= ARRAY;
            id->nr_elm = declare->size / declare->elementsize;
            id->value = (long)data + declare->offset;
            if (declare->offset + declare->size > max_offset)
                max_offset = declare->offset + declare->size;
            declare ++;
        }
        if (max_offset > datasize) {
            datasize += 256;
            data = d = realloc(d, datasize);
            memset(d, 0, datasize);
            declare = save;
            goto restart;
        }
        data += max_offset;
    }

    lp = p = expr_str;

    err = setjmp(synerr_jmp);
    if (err == 0) {
        do {
            next();
            expr(Assign);
        } while (tk == ',');
        *++e = EXIT;
    } else
        goto err_return;

    nr_insn = e - le + 1;

    prog = malloc(sizeof(*prog));
    if (!prog) goto err_return;
    memset(prog, 0, sizeof(*prog));
    prog->symtab = realloc(symtab, nr_syms*sizeof(*symtab));
    prog->nr_syms = nr_syms;
    if (data - d) { prog->data = d; prog->datasize = datasize; }
    else { free(d); prog->data = NULL; prog->datasize = 0; }
    if (str - s) prog->str = s; else { free(s); prog->str = NULL; }
    prog->insn = realloc(le, nr_insn*sizeof(long));
    prog->nr_insn = nr_insn;

    for (i=0; i<prog->nr_syms; i++) {
        struct symbol_table *sym = &prog->symtab[i];
        if (sym->class == Sys && sym->value == KSYM && sym->ref)
            function_resolver_ref();
    }

    return prog;

err_return:
    if (symtab) free(symtab);
    if (d) free(d);
    if (s) free(s);
    if (le) free(le);
    if (prog) free(prog);
    return NULL;
}

long expr_run(struct expr_prog *prog)
{
    long *pc, *sp, *bp, a, cycle; // vm registers
    long i, *t; // temps
    long stack[512];

    pc = prog->insn + 1;
    bp = sp = stack + 512;
    a = 0;
    cycle = 0;
    if (prog->debug) printf("Program running:\n");
    while (1) {
        i = *pc++;
        ++cycle;
        if (prog->debug) {
            if (cycle > 1) printf("; a: 0x%lx\n", a);
            printf("%ld> %.4s", cycle, &INSN[i * 5]);
            if (i <= SI) printf(" 0x%-16lx", *pc); else printf(" %-18s", "");
        }
        switch (i) {
            case LEA: a = (long)(bp + *pc++); break;                              // load local address
            case IMM: a = *pc++; break;                                           // load global address or immediate
            case JMP: pc = (long *)*pc; break;                                    // jump
            case JSR: { *--sp = (long)(pc + 1); pc = (long *)*pc; } break;        // jump to subroutine
            case BZ:  pc = a ? pc + 1 : (long *)*pc; break;                       // branch if zero
            case BNZ: pc = a ? (long *)*pc : pc + 1; break;                       // branch if not zero
            case ENT: { *--sp = (long)bp; bp = sp; sp = sp - *pc++; } break;      // enter subroutine
            case ADJ: sp = sp + *pc++; break;                                     // stack adjust
            case LI:  switch(*pc++) {                                             // load int
                          case sizeof(char): a = *(char *)a; break;
                          case sizeof(short): a = *(short *)a; break;
                          case sizeof(int): a = *(int *)a; break;
                          case sizeof(long): a = *(long *)a; break;
                          default: printf("wrong instruction\n"); return -1;
                      } break;
            case SI:  switch(*pc++) {                                             // store int
                          case sizeof(char): *(char *)*sp++ = a; break;
                          case sizeof(short): *(short *)*sp++ = a; break;
                          case sizeof(int): *(int *)*sp++ = a; break;
                          case sizeof(long): *(long *)*sp++ = a; break;
                          default: printf("wrong instruction\n"); return -1;
                      } break;

            case LEV: { sp = bp; bp = (long *)*sp++; pc = (long *)*sp++; } break; // leave subroutin
            case PSH: *--sp = a; break;                                           // push

            case OR:  a = *sp++ |  a; break;
            case XOR: a = *sp++ ^  a; break;
            case AND: a = *sp++ &  a; break;
            case EQ:  a = *sp++ == a; break;
            case NE:  a = *sp++ != a; break;
            case LT:  a = *sp++ <  a; break;
            case GT:  a = *sp++ >  a; break;
            case LE:  a = *sp++ <= a; break;
            case GE:  a = *sp++ >= a; break;
            case SHL: a = *sp++ << a; break;
            case SHR: a = *sp++ >> a; break;
            case ADD: a = *sp++ +  a; break;
            case SUB: a = *sp++ -  a; break;
            case MUL: a = *sp++ *  a; break;
            case DIV: a = *sp++ /  a; break;
            case MOD: a = *sp++ %  a; break;

            case PRTF: t = sp + pc[1]; a = printf((char *)t[-1], t[-2], t[-3], t[-4], t[-5], t[-6], t[-7]); break;
            case KSYM: a = (long)(void *)ksymbol(*sp); break;
            case NTHL: a = (int)ntohl((int)*sp); break;
            case NTHS: a = (short)ntohs((short)*sp); break;
            case EXIT: if (prog->debug) printf("exit(0x%lx) cycle = %ld\n", a, cycle); return a;
            default: printf("unknown instruction = %ld! cycle = %ld\n", i, cycle); return -1;
        }
    }
}

int expr_load_glo(struct expr_prog *prog, const char *name, long value)
{
    int i;

    if (!prog) return 0;

    for (i=prog->nr_syms-1; i>=0; i--) {
        struct symbol_table *s = &prog->symtab[i];
        if (s->token == Id && s->class == Glo && !memcmp(s->name, name, LEN(s->hash))) {
            switch (s->type) {
                case CHAR: *(char *)s->value = (char)value; break;
                case SHORT: *(short *)s->value = (short)value; break;
                case INT: *(int *)s->value = (int)value; break;
                case LONG: *(long *)s->value = (long)value; break;
                default: return -1;
            }
            return 0;
        }
    }
    return -1;
}

int expr_load_data(struct expr_prog *prog, void *d, int size)
{
    if (!prog || size > prog->datasize) return -1;
    memcpy(prog->data, d, size);
    prog->data[size] = 0;
    return 0;
}

void expr_destroy(struct expr_prog *prog)
{
    int i;

    if (!prog) return;

    for (i=0; i<prog->nr_syms; i++) {
        struct symbol_table *s = &prog->symtab[i];
        if (s->class == Sys && s->value == KSYM && s->ref)
            function_resolver_unref();
    }
    if (prog->symtab) free(prog->symtab);
    if (prog->data) free(prog->data);
    if (prog->str) free(prog->str);
    if (prog->insn) free(prog->insn);
    free(prog);
}

void expr_dump(struct expr_prog *prog)
{
    long *insn_end, *insn;
    int i;

    if (!prog) return;
    insn = prog->insn;
    insn_end = insn+prog->nr_insn-1;

    printf("Instruction:\n");
    while (insn < insn_end) {
        printf("%8.4s", &INSN[*++insn * 5]);
        if (*insn <= SI) printf(" 0x%lx\n", *++insn); else printf("\n");
    }

    if (prog->data) {
        printf("Global variable:\n");
        for (i=0; i<prog->nr_syms; i++) {
            struct symbol_table *s = &prog->symtab[i];
            if (s->token == Id && s->class == Glo) {
                printf("    %16p", (void *)s->value);
                switch (s->type & 0x3) {
                    case CHAR: printf(" char"); break;
                    case SHORT: printf(" short"); break;
                    case INT: printf(" int"); break;
                    case LONG: printf(" long"); break;
                    default: break;
                }
                if (s->type >= PTR) {
                    int t = s->type;
                    printf(" "); do { printf("*"); t -= PTR; } while (t >= PTR);
                }
                if (s->type & ARRAY) printf(" [%d]", s->nr_elm);
                printf(" %.*s\n", (int)LEN(s->hash), s->name);
            }
        }
    }

    if (prog->str) {
        char *c = prog->str;
        printf("Strings:\n");
        while (*c)
            c += printf("    %s\n", c) - 4;
    }
}


/*
 * expr profiler
 *
**/
static struct expression_info {
    char *expression;
    struct expr_prog *prog;
    struct tp_list *tp_list;
} info;

static int expr_argc_init(int argc, char *argv[])
{
    if (argc < 1) {
        fprintf(stderr, " {expression} needs to be specified.\n");
        help();
    } else {
        info.expression = strdup(argv[0]);
    }
    return 0;
}

static int expr_init(struct perf_evlist *evlist, struct env *env)
{
    struct tp_list *tp_list;
    struct global_var_declare *declare;
    struct perf_event_attr attr = {
        .type          = PERF_TYPE_TRACEPOINT,
        .config        = 0,
        .size          = sizeof(struct perf_event_attr),
        .sample_period = 1,
        .sample_type   = PERF_SAMPLE_TID | PERF_SAMPLE_TIME | PERF_SAMPLE_CPU | PERF_SAMPLE_RAW,
        .read_format   = 0,
        .pinned        = 1,
        .disabled      = 1,
        .wakeup_events = 1,
    };
    struct perf_evsel *evsel;
    int i;

    if (!env->event)
        return -1;

    tep__ref();

    tp_list = tp_list_new(env->event);
    if (!tp_list)
        return -1;
    if (tp_list->nr_tp != 1) {
        fprintf(stderr, "Only a single event is allowed to be specified.\n");
        return -1;
    }

    declare = tep__event_fields(tp_list->tp[0].id);
    if (!declare)
        return -1;

    printf("expression: %s\n", info.expression);
    info.prog = expr_compile(info.expression, declare);
    if (!info.prog)
        return -1;
    info.prog->debug = env->verbose;
    expr_dump(info.prog);

    for (i = 0; i < tp_list->nr_tp; i++) {
        struct tp *tp = &tp_list->tp[i];

        attr.config = tp->id;
        evsel = perf_evsel__new(&attr);
        if (!evsel) {
            return -1;
        }
        perf_evlist__add(evlist, evsel);
        tp->evsel = evsel;
    }

    free(declare);
    info.tp_list = tp_list;

    // Only test a small number of events.
    if (env->exit_n == 0) env->exit_n = 5;
    return 0;
}

static int expr_filter(struct perf_evlist *evlist, struct env *env)
{
    int i, err;

    for (i = 0; i < info.tp_list->nr_tp; i++) {
        struct tp *tp = &info.tp_list->tp[i];
        if (tp->filter && tp->filter[0]) {
            err = perf_evsel__apply_filter(tp->evsel, tp->filter);
            if (err < 0)
                return err;
        }
    }
    return 0;
}

static void expr_deinit(struct perf_evlist *evlist)
{
    free(info.expression);
    expr_destroy(info.prog);
    tp_list_free(info.tp_list);
    tep__unref();
}

static void expr_sample(union perf_event *event, int instance)
{
    // in linux/perf_event.h
    // PERF_SAMPLE_TID | PERF_SAMPLE_TIME | PERF_SAMPLE_CPU | PERF_SAMPLE_RAW,
    struct sample_type_header {
        struct {
            __u32    pid;
            __u32    tid;
        }    tid_entry;
        __u64   time;
        struct {
            __u32    cpu;
            __u32    reserved;
        }    cpu_entry;
        struct {
            __u32   size;
            __u8    data[0];
        } raw;
    } *raw = (void *)event->sample.array;
    long result;

    print_time(stdout);
    tep__print_event(raw->time/1000, raw->cpu_entry.cpu, raw->raw.data, raw->raw.size);

    expr_load_data(info.prog, raw->raw.data, raw->raw.size);
    result = expr_run(info.prog);
    printf("result: 0x%lx\n", result);
}

static void expr_help(struct help_ctx *hctx)
{
    struct tp *tp = &hctx->tp_list[0]->tp[0];

    printf(PROGRAME " expr ");
    printf("-e \"");
    printf("%s:%s/%s/", tp->sys, tp->name, tp->filter&&tp->filter[0]?tp->filter:".");
    printf("\" {expression} ");

    common_help(hctx, true, true, true, false, false, true, true);
    common_help(hctx, false, true, true, false, false, true, true);
    printf("\n");
}

static const char *expr_desc[] = PROFILER_DESC("expr",
    "[OPTION...] {expression}",
    "Expression compiler and simulator.", "",
    "SYNOPSIS",
    "    Expressions are first compiled into assembly instructions, which can then be",
    "    simulated and executed multiple times. Expressions can use global variables,",
    "    which come from tracepoint fields.",
    "",
    "SYNTAX",
    "    Supports 4 integer types: char, short, int, long. and pointer types.",
    "    Most operators are supported. See Operators.",
    "    Supports 2 built-in functions. See Built-in Functions.",
    "",
    "  Operators",
    "    Precedence  Operator    Description",
    "    1           ++ --       Suffix/postfix increment and decrement",
    "                ()          Function call",
    "                []          Array subscripting",
    "    2           ++ --       Prefix increment and decrement",
    "                + -         Unary plus and minus",
    "                ! ~         Logical NOT and bitwise NOT",
    "                (type)      Cast",
    "                *           Indirection (dereference)",
    "                &           Address-of",
    "                sizeof      Size-of",
    "    3           * / %       Multiplication, division, and remainder",
    "    4           + -         Addition and subtraction",
    "    5           << >>       Bitwise left shift and right shift",
    "    6           < <=        For relational operators < and <= respectively",
    "                > >=        For relational operators > and >= respectively",
    "    7           == !=       For relational = and != respectively",
    "    8           &           Bitwise AND",
    "    9           ^           Bitwise XOR (exclusive or)",
    "    10          |           Bitwise OR (inclusive or)",
    "    11          &&          Logical AND",
    "    12          ||          Logical OR",
    "    13          ?:          Ternary conditional",
    "    14          =           Simple assignment",
    "    15          ,           Comma",
    "",
    "  Built-in Functions",
    "    int printf(char *fmt, args...)",
    "        Prints args according to fmt, and return the number of characters",
    "        printed, args can take up to 6 variable parameters.",
    "",
    "    char *ksymbol(long addr)",
    "        Get the kernel symbol name according to addr, and return a string.",
    "",
    "    int ntohl(int netlong)",
    "    short ntohs(short netshort)",
    "        These functions convert network byte order to host byte order.",
    "",
    "EXAMPLES",
    "    "PROGRAME" expr -e sched:sched_wakeup help",
    "    "PROGRAME" expr -e sched:sched_wakeup '&pid'",
    "    "PROGRAME" expr -e 'kmem:mm_page_alloc/order>0/' '1<<order' -v",
    "    "PROGRAME" expr -e workqueue:workqueue_execute_start 'printf(\"%s \", ksymbol(function))' -v",
    "    "PROGRAME" expr -e sched:sched_process_exec 'printf(\"%s \", (char *)&common_type + filename_offset)'"
);
static const char *expr_argv[] = PROFILER_ARGV("expr",
    "OPTION:",
    "cpus", "pids", "tids", "output", "mmap-pages", "exit-N",
    "version", "verbose", "quiet", "help",
    PROFILER_ARGV_PROFILER, "event"
);
static profiler _expr = {
    .name = "expr",
    .desc = expr_desc,
    .argv = expr_argv,
    .pages = 2,
    .help = expr_help,
    .argc_init = expr_argc_init,
    .init = expr_init,
    .filter = expr_filter,
    .deinit = expr_deinit,
    .sample = expr_sample,
};
PROFILER_REGISTER(_expr);

