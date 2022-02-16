MACRO (aco_register_test test)
  SET(name ${test})

  ADD_EXECUTABLE(test_${name} ${name}.cc)
  ADD_TEST(test_${name} test_${name})
  ADD_DEPENDENCIES(check test_${name})
  ADD_DEPENDENCIES(test_${name} libaco::aco)

  ACO_TARGET_CONFIGURE(test_${name} libaco::aco ${ARGN})
ENDMACRO ()

MACRO (aco_register_bench bench)
  SET(name ${bench})

  ADD_EXECUTABLE(bench_${name} ${name}.cc)
  ADD_DEPENDENCIES(bench_${name} libaco::aco)

  ACO_TARGET_CONFIGURE(bench_${name} libaco::aco ${ARGN})
ENDMACRO ()

ACO_REGISTER_TEST(synopsis)
ACO_REGISTER_TEST(tutorial_0)
ACO_REGISTER_TEST(tutorial_1)
ACO_REGISTER_TEST(tutorial_2)
ACO_REGISTER_TEST(tutorial_3)
ACO_REGISTER_TEST(tutorial_4)
ACO_REGISTER_TEST(tutorial_5)
ACO_REGISTER_TEST(tutorial_6)
ACO_REGISTER_TEST(tutorial_7)
ACO_REGISTER_TEST(tutorial_8)

ACO_REGISTER_BENCH(benchmark)

# timer wheel
ACO_REGISTER_TEST(timewheel_basic)
ACO_REGISTER_BENCH(timewheel_benchmark)
