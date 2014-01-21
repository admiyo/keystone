# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.


from keystone.contrib import revoke


#This implementation is to allow the revoke code to be integrated into the
#providers unconditionally, but to bypass recording or reporting actual events.
#Instead, this implementation drops all events. Since the in memory KVS
#implementation does not clean up expired events, it would be unsafe to use as
#the default.
class Revoke(revoke.Driver):

    def get_events(self, filter=None):
        """:returns: []

        """
        return []

    def revoke(self, event):
        """Does nothing.
        """
        pass
