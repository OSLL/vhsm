#include "VhsmTest.h"
#include <cppunit/extensions/TestFactoryRegistry.h>
#include <cppunit/ui/text/TextTestRunner.h>

CPPUNIT_TEST_SUITE_REGISTRATION ( VhsmTest );

int main ()
{
  CppUnit::Test *test = CppUnit::TestFactoryRegistry::getRegistry().makeTest();
  CppUnit::TextTestRunner runner;
  runner.addTest(test);

  runner.run();

  return 0;
}
