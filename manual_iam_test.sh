#!/bin/bash
GROUP="$1"

accounts=$(yq r ~/.saml2aws-auto.yml 'groups.'"$GROUP"'.accounts[*].name' | awk '{print $2}')

for a in $accounts; do
	printf "Testing %s" "$a"

	iam_alias="$(aws --profile "$a" iam list-account-aliases --output text --query 'AccountAliases[0]')"

	if [ "$a" != "$iam_alias" ]; then
		printf " FAIL. Expected %s, got %s\\n" "$a" "$iam_alias"
	else
		printf " SUCCESS\\n"
	fi
done

