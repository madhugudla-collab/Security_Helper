# Security Analysis: Either re-interrupt this method or rethrow the "InterruptedE

**Tool:** sonarqube | **Language:** python
**Findings:** 5

## Affected Locations

- `src/main/java/org/t246osslab/easybuggy/errors/OutOfMemoryErrorServlet3.java` line 25: Either re-interrupt this method or rethrow the "InterruptedException" that can be caught here. (java:S2142)
- `src/main/java/org/t246osslab/easybuggy/exceptions/IllegalMonitorStateExceptionServlet.java` line 22: Either re-interrupt this method or rethrow the "InterruptedException" that can be caught here. (java:S2142)
- `src/main/java/org/t246osslab/easybuggy/troubles/DeadlockServlet.java` line 90: Either re-interrupt this method or rethrow the "InterruptedException" that can be caught here. (java:S2142)
- `src/main/java/org/t246osslab/easybuggy/troubles/DeadlockServlet2.java` line 176: Either re-interrupt this method or rethrow the "InterruptedException" that can be caught here. (java:S2142)
- `src/main/java/org/t246osslab/easybuggy/troubles/EndlessWaitingServlet.java` line 72: Either re-interrupt this method or rethrow the "InterruptedException" that can be caught here. (java:S2142)
