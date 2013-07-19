#include "MessageHandlerTest.h"

CPPUNIT_TEST_SUITE_REGISTRATION ( MessageHandlerTest );

int main ()
{
  CppUnit::Test *test = CppUnit::TestFactoryRegistry::getRegistry().makeTest();
  CppUnit::TextTestRunner runner;
  runner.addTest(test);

  runner.run();
    VHSM v;
  return 0;
}
