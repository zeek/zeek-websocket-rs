import test from "ava";

import { deserializeJson, Event, Message, serializeJson } from "../../../../index";

const SERIALIZED = {
  type: "data-message",
  topic: "/topic",
  "@data-type": "vector",
  data: [
    {
      "@data-type": "count",
      data: 1,
    },
    {
      "@data-type": "count",
      data: 1,
    },
    {
      "@data-type": "vector",
      data: [
        {
          "@data-type": "string",
          data: "foo",
        },
        {
          "@data-type": "vector",
          data: [
            {
              "@data-type": "count",
              data: 42,
            },
            {
              "@data-type": "string",
              data: "abc",
            },
          ],
        },
        {
          "@data-type": "vector",
          data: [],
        },
      ],
    },
  ],
};

const EVENT: Event = {
  name: "foo",
  args: [
    {
      type: "Count",
      value: 42n,
    },
    {
      type: "String",
      value: "abc",
    },
  ],
  metadata: [],
};

test("serialize event", (t) => {
  const message: Message = {
    type: "Event",
    topic: "/topic",
    event: EVENT,
  };

  t.deepEqual(JSON.parse(serializeJson(message)), SERIALIZED);
});

test("deserialize event", (t) => {
  const message = deserializeJson(JSON.stringify(SERIALIZED));

  switch (message.type) {
    case "Event":
      t.deepEqual(message.event, EVENT);
      break;
    default:
      t.fail(`event expected, got ${message.type}`);
  }
});
