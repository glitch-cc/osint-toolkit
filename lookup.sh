#!/bin/bash
# OSINT Quick Lookup - Proof of Concept
# Usage: ./lookup.sh "Company Name" or ./lookup.sh "Person Name" "Company"

source /root/.openclaw/.secure/keys.env

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

if [ -z "$1" ]; then
    echo "Usage: ./lookup.sh 'Company Name' OR ./lookup.sh 'Person Name' 'Company'"
    exit 1
fi

if [ -z "$2" ]; then
    # Company-only lookup
    COMPANY="$1"
    echo -e "${BLUE}=== Company Brief: $COMPANY ===${NC}"
    echo ""
    
    # Perplexity query
    RESPONSE=$(curl -s "https://api.perplexity.ai/chat/completions" \
      -H "Authorization: Bearer $PERPLEXITY_API_KEY" \
      -H "Content-Type: application/json" \
      --data-raw "{\"model\": \"sonar\", \"messages\": [{\"role\": \"user\", \"content\": \"Brief on ${COMPANY}: what they do (1 sentence), HQ location, employee count, key leadership. Be concise.\"}]}")
else
    # Person + Company lookup
    PERSON="$1"
    COMPANY="$2"
    echo -e "${BLUE}=== Person Brief: $PERSON @ $COMPANY ===${NC}"
    echo ""
    
    RESPONSE=$(curl -s "https://api.perplexity.ai/chat/completions" \
      -H "Authorization: Bearer $PERPLEXITY_API_KEY" \
      -H "Content-Type: application/json" \
      --data-raw "{\"model\": \"sonar\", \"messages\": [{\"role\": \"user\", \"content\": \"30-second networking brief on ${PERSON} at ${COMPANY}: their role, company background, recent news, 2 conversation starters. Concise.\"}]}")
fi

# Extract and display
echo -e "${GREEN}--- Intelligence Brief ---${NC}"
echo "$RESPONSE" | jq -r '.choices[0].message.content' 2>/dev/null
echo ""

# Show citations
echo -e "${YELLOW}--- Sources ---${NC}"
echo "$RESPONSE" | jq -r '.citations[:3][]' 2>/dev/null
echo ""

# Cost tracking
COST=$(echo "$RESPONSE" | jq -r '.usage.cost.total_cost' 2>/dev/null)
echo -e "Query cost: \$${COST:-unknown}"
echo -e "${BLUE}=== End Brief ===${NC}"
