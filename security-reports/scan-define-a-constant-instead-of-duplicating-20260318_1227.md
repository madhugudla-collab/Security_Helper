# Security Analysis: Define a constant instead of duplicating this literal "','fa

**Tool:** sonarqube | **Language:** python
**Findings:** 23

## Affected Locations

- `src/main/java/org/t246osslab/easybuggy/core/dao/DBClient.java` line 75: Define a constant instead of duplicating this literal "','false', '', '')" 4 times. (java:S1192)
- `src/main/java/org/t246osslab/easybuggy/core/dao/DBClient.java` line 81: Define a constant instead of duplicating this literal "','true', '', '')" 10 times. (java:S1192)
- `src/main/java/org/t246osslab/easybuggy/core/dao/EmbeddedADS.java` line 60: Define a constant instead of duplicating this literal "objectClass" 3 times. (java:S1192)
- `src/main/java/org/t246osslab/easybuggy/core/filters/AuthenticationFilter.java` line 59: Define a constant instead of duplicating this literal "/login" 3 times. (java:S1192)
- `src/main/java/org/t246osslab/easybuggy/core/servlets/AbstractServlet.java` line 79: Define a constant instead of duplicating this literal "</td>" 3 times. (java:S1192)
- `src/main/java/org/t246osslab/easybuggy/core/servlets/AdminsMainServlet.java` line 21: Define a constant instead of duplicating this literal "<li><a href=\"" 3 times. (java:S1192)
- `src/main/java/org/t246osslab/easybuggy/core/servlets/AdminsMainServlet.java` line 22: Define a constant instead of duplicating this literal "</a></li>" 3 times. (java:S1192)
- `src/main/java/org/t246osslab/easybuggy/core/servlets/DefaultLoginServlet.java` line 45: Define a constant instead of duplicating this literal "</tr>" 3 times. (java:S1192)
- `src/main/java/org/t246osslab/easybuggy/core/servlets/DefaultLoginServlet.java` line 71: Define a constant instead of duplicating this literal "authNMsg" 5 times. (java:S1192)
- `src/main/java/org/t246osslab/easybuggy/core/utils/ApplicationUtils.java` line 176: Define a constant instead of duplicating this literal "Exception occurs: " 3 times. (java:S1192)
- `src/main/java/org/t246osslab/easybuggy/core/utils/Closer.java` line 35: Define a constant instead of duplicating this literal "IOException occurs: " 4 times. (java:S1192)
- `src/main/java/org/t246osslab/easybuggy/performance/CreatingUnnecessaryObjectsServlet.java` line 32: Define a constant instead of duplicating this literal "<br><br>" 3 times. (java:S1192)
- `src/main/java/org/t246osslab/easybuggy/performance/SlowRegularExpressionServlet.java` line 32: Define a constant instead of duplicating this literal "<br><br>" 5 times. (java:S1192)
- `src/main/java/org/t246osslab/easybuggy/performance/StringPlusOperationServlet.java` line 41: Define a constant instead of duplicating this literal "<br><br>" 5 times. (java:S1192)
- `src/main/java/org/t246osslab/easybuggy/troubles/DBConnectionLeakServlet.java` line 43: Define a constant instead of duplicating this literal "Exception occurs: " 3 times. (java:S1192)
- `src/main/java/org/t246osslab/easybuggy/troubles/DBConnectionLeakServlet.java` line 71: Define a constant instead of duplicating this literal "</td><td>" 3 times. (java:S1192)
- `src/main/java/org/t246osslab/easybuggy/troubles/DBConnectionLeakServlet.java` line 76: Define a constant instead of duplicating this literal "</th><th>" 3 times. (java:S1192)
- `src/main/java/org/t246osslab/easybuggy/troubles/DeadlockServlet2.java` line 57: Define a constant instead of duplicating this literal "Exception occurs: " 3 times. (java:S1192)
- `src/main/java/org/t246osslab/easybuggy/troubles/DeadlockServlet2.java` line 59: Define a constant instead of duplicating this literal "msg.unknown.exception.occur" 3 times. (java:S1192)
- `src/main/java/org/t246osslab/easybuggy/troubles/DeadlockServlet2.java` line 81: Define a constant instead of duplicating this literal "<br><br>" 3 times. (java:S1192)
- `src/main/java/org/t246osslab/easybuggy/troubles/DeadlockServlet2.java` line 100: Define a constant instead of duplicating this literal "<td><input type=\"text\" name=\"" 3 times. (java:S1192)
- `src/main/java/org/t246osslab/easybuggy/troubles/DeadlockServlet2.java` line 135: Define a constant instead of duplicating this literal "SQLException occurs: " 3 times. (java:S1192)
- `src/main/java/org/t246osslab/easybuggy/troubles/EndlessWaitingServlet.java` line 38: Define a constant instead of duplicating this literal "<br><br>" 5 times. (java:S1192)
