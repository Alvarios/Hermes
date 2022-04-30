# -*- coding: utf-8 -*-
"""Messages codes for unified communication code system.

    Use these constant when needed instead of raw value to prevent issues in
    case of future changes.

    Copyright (C) 2020  Clement Dulouard

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as published
    by the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.

Also add information on how to contact you by electronic and paper mail.

  If your software can interact with users remotely through a computer
network, you should also make sure that it provides a way for users to
get its source.  For example, if your program is a web application, its
interface could display a "Source" link that leads users to an archive
of the code.  There are many ways you could offer source, and different
solutions will be better for different programs; see section 13 for the
specific requirements.

  You should also get your employer (if you work as a programmer) or school,
if any, to sign a "copyright disclaimer" for the program, if necessary.
For more information on this, and how to apply and follow the GNU AGPL, see
<https://www.gnu.org/licenses/>.
"""

"""
Verbs [0-99]
"""
HEALTH_CHECK = 0
GET = 1
HEAD = 2
POST = 3
PUT = 4
DELETE = 5
CONNECT = 6
OPTIONS = 7
TRACE = 8
PATCH = 9

"""
Status code [100 - 999]
"""
CONTINUE = 100
PROCESSING = 102

OK = 200
NO_CONTENT = 204
PARTIAL_CONTENT = 206

BAD_REQUEST = 400
UNAUTHORIZED = 401
FORBIDDEN = 403
TOO_MANY_REQUEST = 429

NOT_IMPLEMENTED = 501
NETWORK_AUTHENTICATION_REQUIRED = 511
UNKNOWN_ERROR = 520

"""
Alvarios reserved codes [1000 - 9999]
"""

HANDSHAKE = 1020
VIDEO_STREAM = 1100
