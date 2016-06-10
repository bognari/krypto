import org.junit.Test;

import java.io.IOException;

public class TestCaesar {
    @Test(timeout = TestHelper.TEST_TIMEOUT)
    public void Kanga_testBaseProgram() throws IOException, InterruptedException, Parser.Exception {
        AllTests.testBaseProgram(TestHelper::buildKanga, TestHelper::runKangaInterpreter);
    }
}