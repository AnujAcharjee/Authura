declare module 'ejs-mate' {
  type Engine = (
    path: string,
    options: Record<string, any>,
    callback: (err: any, rendered?: string) => void,
  ) => void;

  const engine: Engine;
  export = engine;
}
