# Sign AWS Request

This tool will take a request, creds from EKS or local credentials, and proxy using the provided creds.

## Motivation

Use Amazon ElasticSearch with [Fine-Grained Access Control](https://docs.aws.amazon.com/elasticsearch-service/latest/developerguide/fgac.html) enabled.

With FGAC, you must either use a username and password (yuck) or AWS Cognito (meh).
When there is already an auto mechanism that works, why throw Yet Another Thing to Go Wrong
into the mix?

The tool is able to sit in front of ES (and Kibana) and grant a role to whoever can get access.

This should **never** be deployed listening on `0.0.0.0`! Always listen on localhost, and have the
auth proxy point to it inside the same Pod. (They will be on the same network.)

### Why build something

For fun! :-D ... also

While there ware a few tools that can do something similar. They are all
lacking in some way. The motivations here were:

- Something supported (quite a few of the ones out there aren't :-/)
- Something that targets a specific host
- Something that supports EKS out of the box.
- Support for ES's url params (same one multiple times)

It's surprising how few tools support EKS out of the box.

## Deploying


1. Create a IAM Role that has permissions to talk to the ES cluster for this service.
2. Add permissions to Kibana for the new Role. This is done via the `BackendRoles` in Kibana.
   You will need to use the `Role Mapping` not the `User` config to do this. The role should have
   `kibana-user` and what ever role has permissions to the index you want.
3. Deploy this service along side the auth proxy using the previous IAM Role as the TaskRole.
4. (Optional) If your using cross cluster search, add the Role from 1 in the Kibana for all the
   downstream Kibana's as well with the same permissions.