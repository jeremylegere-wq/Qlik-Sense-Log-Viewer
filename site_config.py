"""Everything specific to one Qlik site, in one place: the log share, the fault form, the ticket system, the login service.

Fill these in for your own Qlik Sense server. Leave a value empty to turn that feature off. The log folder and the
fault form can also be set per PC with the QLIK_ARCHIVE_ROOT and QLIK_FAULT_URL environment variables, which win over
the values here.
"""


# The ArchivedLogs folder for the Qlik node (UNC path), e.g. r"\\qlikserver\QlikShare$\ArchivedLogs\qlikserver".
# Empty: nothing is pre-filled and you type or paste the path in the app.
ARCHIVE_ROOT = r""

# How the server is named in summaries you paste elsewhere.
SERVER_LABEL = "Qlik Sense server"

# The form for raising a fault, opened by the "Log a fault" buttons. Empty hides the buttons.
FAULT_URL = ""
FAULT_SYSTEM = "service desk"                                           # what the fault form belongs to
FAULT_FORM_NAME = "service desk form"

# Ticket references: placeholder text, and the Jira project the Rovo prompt files bugs in (empty: no project key).
TICKET_HINT = "INC… or PROJ-…"
JIRA_PROJECT = ""

# The service users log in through before the Qlik proxy gives them a session (an identity provider or SSO portal).
LOGIN_SERVICE = "login service"
LOGIN_SERVICE_HINT = "The login service or identity provider in front of Qlik, and the network path from the user"

# The time zone people report problems in: its name and minutes east of UTC. LOCAL_TZ_MIN = None uses this PC's time zone.
LOCAL_TZ_NAME = ""
LOCAL_TZ_MIN = None

# The Qlik server's size: the starting values in Server settings.
SERVER_CORES = 16
SERVER_RAM_GB = 128
