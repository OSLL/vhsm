#include "VhsmStorageTest.h"
#include <cppunit/extensions/TestFactoryRegistry.h>
#include <cppunit/ui/text/TextTestRunner.h>
#include <unistd.h>

CPPUNIT_TEST_SUITE_REGISTRATION ( VhsmStorageTest );

int main ()
{
  CppUnit::Test *test = CppUnit::TestFactoryRegistry::getRegistry().makeTest();
  CppUnit::TextTestRunner runner;
  runner.addTest(test);

  runner.run();

  unlink("keys.db");

  return 0;
}
