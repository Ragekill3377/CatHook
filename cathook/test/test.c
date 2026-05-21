#include "cathook.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

static int  g_hook_called = 0;
static int  g_orig_result = 0;
static int  g_rep_result  = 0;

static int (*g_original_add)(int, int) = NULL;

static int target_add(int a, int b)  { return a + b; }

__attribute__((used))
static int replacement_add(int a, int b)
{
    g_hook_called = 1;
    g_orig_result = g_original_add(a, b);
    g_rep_result  = a * b;
    return g_rep_result;
}

static int test_basic_hook(void)
{
    g_hook_called = 0;
    assert(ch_hook((void *)target_add, (void *)replacement_add,
                   (void **)&g_original_add) == 0);
    assert(target_add(3, 5) == 15);
    assert(g_hook_called == 1);
    assert(g_orig_result == 8);
    assert(g_rep_result == 15);
    return 1;
}

static int test_original_trampoline(void)
{
    assert(g_original_add(10, 20) == 30);
    return 1;
}

static int test_unhook(void)
{
    assert(ch_unhook((void *)target_add) == 0);
    g_hook_called = 0;
    assert(target_add(7, 8) == 15);
    assert(g_hook_called == 0);
    return 1;
}

static int test_double_hook(void)
{
    assert(ch_hook((void *)target_add, (void *)replacement_add,
                   (void **)&g_original_add) == 0);
    assert(ch_hook((void *)target_add, (void *)replacement_add,
                   (void **)&g_original_add) != 0);
    ch_unhook((void *)target_add);
    return 1;
}

static int  g_leaf_called = 0;
static int (*g_leaf_orig)(int) = NULL;

static int leaf_fn(int x) { return x * 2; }

__attribute__((used))
static int leaf_rep(int x)
{
    g_leaf_called = 1;
    return g_leaf_orig(x) + 100;
}

static int test_leaf_function(void)
{
    g_leaf_called = 0;
    assert(ch_hook((void *)leaf_fn, (void *)leaf_rep,
                   (void **)&g_leaf_orig) == 0);
    assert(leaf_fn(5) == 110);
    assert(g_leaf_called == 1);
    ch_unhook((void *)leaf_fn);
    assert(leaf_fn(5) == 10);
    return 1;
}

static int   g_strlen_called = 0;
static size_t (*g_strlen_orig)(const char *) = NULL;

__attribute__((used))
static size_t strlen_rep(const char *s)
{
    g_strlen_called = 1;
    return g_strlen_orig(s) + 1;
}

static int test_strlen_hook(void)
{
    g_strlen_called = 0;
    assert(ch_hook((void *)strlen, (void *)strlen_rep,
                   (void **)&g_strlen_orig) == 0);
    assert(strlen("hello") == 6);
    assert(g_strlen_called == 1);
    ch_unhook((void *)strlen);
    assert(strlen("hello") == 5);
    return 1;
}

__attribute__((used))
static int stress_fn(int a, int b, int c, int d)
{
    int sum = a + b + c + d;
    int x = sum;
    for (int i = 0; i < 4; i++) x += i;
    return x;
}

__attribute__((used))
static int stress_rep(int a, int b, int c, int d)
{
    (void)a; (void)b; (void)c; (void)d;
    return 1000;
}

static int test_stress_rehook(void)
{
    int (*orig)(int, int, int, int) = NULL;
    (void)orig;

    for (int i = 0; i < 100; i++) {
        assert(ch_hook((void *)stress_fn, (void *)stress_rep,
                       (void **)&orig) == 0);
        assert(stress_fn(1, 2, 3, 4) == 1000);
        assert(ch_unhook((void *)stress_fn) == 0);
        assert(stress_fn(1, 2, 3, 4) == 16);
    }
    return 1;
}

__attribute__((used))
static int branchy_fn(int x)
{
    if (x > 10) return x * 2;
    if (x > 5)  return x + 10;
    return x;
}

__attribute__((used))
static int branchy_rep(int x)
{
    return x + 999;
}

static int test_branchy_hook(void)
{
    int (*orig)(int) = NULL;
    (void)orig;
    assert(ch_hook((void *)branchy_fn, (void *)branchy_rep,
                   (void **)&orig) == 0);
    assert(branchy_fn(3) == 1002);
    assert(branchy_fn(7) == 1006);
    assert(branchy_fn(20) == 1019);
    assert(orig(5) == 5);
    ch_unhook((void *)branchy_fn);
    assert(branchy_fn(5) == 5);
    return 1;
}

int main(void)
{
    int passed = 0;
    int total  = 0;

    printf("=== cathook tests ===\n\n");

    printf("[%d] basic hook     ", ++total); fflush(stdout);
    test_basic_hook();       printf("PASS\n"); passed++;

    printf("[%d] trampoline     ", ++total); fflush(stdout);
    test_original_trampoline(); printf("PASS\n"); passed++;

    printf("[%d] unhook         ", ++total); fflush(stdout);
    test_unhook();           printf("PASS\n"); passed++;

    printf("[%d] double hook    ", ++total); fflush(stdout);
    test_double_hook();      printf("PASS\n"); passed++;

    printf("[%d] leaf function  ", ++total); fflush(stdout);
    test_leaf_function();    printf("PASS\n"); passed++;

    printf("[%d] strlen hook    ", ++total); fflush(stdout);
    test_strlen_hook();      printf("PASS\n"); passed++;

    printf("[%d] stress rehook  ", ++total); fflush(stdout);
    test_stress_rehook();    printf("PASS\n"); passed++;

    printf("[%d] branchy hook   ", ++total); fflush(stdout);
    test_branchy_hook();     printf("PASS\n"); passed++;

    printf("\n%d/%d tests passed\n", passed, total);
    return passed == total ? 0 : 1;
}
