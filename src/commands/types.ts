export type CommandContext = {
  args: string;
  agentId: string;
  senderId: string;
  channelId: string;
};

export type CommandResult = {
  text: string;
};
